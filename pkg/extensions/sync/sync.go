package sync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver"
	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	"gopkg.in/resty.v1"
)

const (
	maxRetries = 3
	delay      = 5 * time.Minute
)

var certsDir = fmt.Sprintf("%s/zot-certs-dir/", os.TempDir()) //nolint: gochecknoglobals

var locker sync.Mutex //nolint: gochecknoglobals

// /v2/_catalog struct.
type catalog struct {
	Repositories []string `json:"repositories"`
}

type RegistryConfig struct {
	URL          string
	PollInterval time.Duration
	Credentials  types.DockerAuthConfig
	Content      []Content
	TLSVerify    bool
	CertDir      string
}

type Content struct {
	Prefix string
	Tags   *Tags
}

type Tags struct {
	Regex  *string
	Semver *bool
}

type PostHandler struct {
	Address    string
	Port       string
	ServerCert string
	ServerKey  string
	CACert     string
	Cfg        []RegistryConfig
	Log        log.Logger
}

func (h *PostHandler) Handler(w http.ResponseWriter, r *http.Request) {
	destCtx, policyContext, err := getDestContexts(h.ServerCert, h.ServerKey, h.CACert)
	if err != nil {
		WriteData(w, http.StatusInternalServerError, err.Error())

		return
	}

	defer policyContext.Destroy() //nolint: errcheck

	destRegistry := fmt.Sprintf("%s:%s", h.Address, h.Port)

	for _, regCfg := range h.Cfg {
		if err := syncRegistry(regCfg, h.Log, destRegistry, destCtx, policyContext); err != nil {
			h.Log.Err(err).Msg("Error while syncing")
			WriteData(w, http.StatusInternalServerError, err.Error())

			return
		}
	}

	WriteData(w, http.StatusOK, "")
}

func WriteData(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// getCatalog gets all repos from a registry.
func getCatalog(regCfg RegistryConfig) (catalog, error) {
	var c catalog

	registryCatalogURL := fmt.Sprintf("%s%s", regCfg.URL, "/v2/_catalog")
	client := resty.New()

	if regCfg.TLSVerify {
		clientCert := fmt.Sprintf("%s/client.cert", regCfg.CertDir)
		clientKey := fmt.Sprintf("%s/client.key", regCfg.CertDir)
		caCertPath := fmt.Sprintf("%s/ca.crt", regCfg.CertDir)

		caCert, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			return c, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})

		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return c, err
		}

		client.SetCertificates(cert)
	}

	if regCfg.Credentials != (types.DockerAuthConfig{}) {
		client.SetBasicAuth(regCfg.Credentials.Username, regCfg.Credentials.Password)
	}

	resp, err := client.R().SetHeader("Content-Type", "application/json").Get(registryCatalogURL)
	if err != nil {
		return c, err
	}

	err = json.Unmarshal(resp.Body(), &c)
	if err != nil {
		return c, err
	}

	return c, nil
}

// filterRepos filters repos based on prefix given in the config.
func filterRepos(repos []string, content []Content) []string {
	var filtered []string

	for _, repo := range repos {
		for _, c := range content {
			if strings.HasPrefix(repo, c.Prefix) {
				filtered = append(filtered, repo)
			}
		}
	}

	return filtered
}

// parseRepositoryReference parses input into a reference.Named, and verifies that it names a repository, not an image.
func parseRepositoryReference(input string) (reference.Named, error) {
	ref, err := reference.ParseNormalizedNamed(input)
	if err != nil {
		return nil, err
	}

	if !reference.IsNameOnly(ref) {
		return nil, errors.ErrInvalidRepositoryName
	}

	return ref, nil
}

// getImageTags lists all tags in a repository.
// It returns a string slice of tags and any error encountered.
func getImageTags(ctx context.Context, sysCtx *types.SystemContext, repoRef reference.Named) ([]string, error) {
	dockerRef, err := docker.NewReference(reference.TagNameOnly(repoRef))
	if err != nil {
		return nil, err // Should never happen for a reference with tag and no digest
	}

	tags, err := docker.GetRepositoryTags(ctx, sysCtx, dockerRef)
	if err != nil {
		return nil, err
	}

	return tags, nil
}

// getTagFromRef returns a tagged reference from an image reference.
func getTagFromRef(ref types.ImageReference, log log.Logger) reference.Tagged {
	tagged, isTagged := ref.DockerReference().(reference.Tagged)
	if !isTagged {
		log.Warn().Msgf("Internal error, reference %s does not have a tag, skipping", ref.DockerReference())
		return nil
	}

	return tagged
}

// filterImagesByTagRegex filters images by tag regex give in the config.
func filterImagesByTagRegex(sourceReferences *[]types.ImageReference, content []Content, log log.Logger) error {
	log.Info().Msgf("Start filtering using the regular expression: %#v", content)

	refs := *sourceReferences

	for _, c := range content {
		if c.Tags == nil {
			continue
		}

		if c.Tags.Regex != nil {
			tagReg, err := regexp.Compile(*c.Tags.Regex)
			if err != nil {
				return err
			}

			for i := 0; i < len(refs); i++ {
				tagged := getTagFromRef(refs[i], log)
				if tagged == nil {
					continue
				}

				if !tagReg.MatchString(tagged.Tag()) {
					refs = append(refs[:i], refs[i+1:]...)
					i--
				}
			}
		}
	}

	*sourceReferences = refs

	return nil
}

// filterImagesBySemver filters images by checking if their tags are semver compliant.
func filterImagesBySemver(sourceReferences *[]types.ImageReference, content []Content, log log.Logger) {
	log.Info().Msg("Start filtering using semver compliant rule")

	refs := *sourceReferences

	for _, c := range content {
		if c.Tags == nil {
			continue
		}

		if c.Tags.Semver != nil {
			for i := 0; i < len(refs); i++ {
				tagged := getTagFromRef(refs[i], log)
				if tagged == nil {
					continue
				}

				_, ok := semver.NewVersion(tagged.Tag())
				if ok != nil {
					log.Info().Msgf("tag %s is not semver, skipping", tagged.Tag())

					refs = append(refs[:i], refs[i+1:]...)
					i--
				}
			}
		}
	}

	*sourceReferences = refs
}

// imagesToCopyFromRepos lists all images given a registry name and its repos.
func imagesToCopyFromRepos(registryName string, repos []string, sourceCtx *types.SystemContext,
	content []Content, log log.Logger) ([]types.ImageReference, error) {
	var sourceReferences []types.ImageReference

	for _, repoName := range repos {
		repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", registryName, repoName))
		if err != nil {
			return nil, err
		}

		tags, err := getImageTags(context.Background(), sourceCtx, repoRef)
		if err != nil {
			return nil, err
		}

		for _, tag := range tags {
			taggedRef, err := reference.WithTag(repoRef, tag)
			if err != nil {
				log.Err(err).Msgf("Error creating a reference for repository %s and tag %q", repoRef.Name(), tag)
				return nil, err
			}

			ref, err := docker.NewReference(taggedRef)
			if err != nil {
				log.Err(err).Msgf("Cannot obtain a valid image reference for transport %q and reference %s",
					docker.Transport.Name(), taggedRef.String())
				return nil, err
			}

			sourceReferences = append(sourceReferences, ref)
		}
	}

	err := filterImagesByTagRegex(&sourceReferences, content, log)
	if err != nil {
		return []types.ImageReference{}, err
	}

	filterImagesBySemver(&sourceReferences, content, log)

	return sourceReferences, nil
}

func syncRegistry(regCfg RegistryConfig, log log.Logger, destRegistry string, destCtx *types.SystemContext,
	policyCtx *signature.PolicyContext) error {
	locker.Lock()
	defer locker.Unlock()

	log.Info().Msgf("Syncing registry: %s", regCfg.URL)

	srcCtx := &types.SystemContext{}
	if regCfg.TLSVerify {
		srcCtx.DockerCertPath = regCfg.CertDir
		srcCtx.DockerDaemonCertPath = regCfg.CertDir
		srcCtx.DockerDaemonInsecureSkipTLSVerify = false
		srcCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(false)
	} else {
		srcCtx.DockerDaemonInsecureSkipTLSVerify = true
		srcCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(true)
	}

	if regCfg.Credentials != (types.DockerAuthConfig{}) {
		srcCtx.DockerAuthConfig = &regCfg.Credentials
	}

	options := copy.Options{
		DestinationCtx: destCtx,
		SourceCtx:      srcCtx,
		ReportWriter:   os.Stdout,
	}

	retryOptions := &retry.RetryOptions{
		MaxRetry: maxRetries,
		Delay:    delay,
	}

	var err error

	var catalog catalog

	if err = retry.RetryIfNecessary(context.Background(), func() error {
		catalog, err = getCatalog(regCfg)
		return err
	}, retryOptions); err != nil {
		return err
	}

	registryName := strings.Replace(strings.Replace(regCfg.URL, "http://", "", 1), "https://", "", 1)

	repos := filterRepos(catalog.Repositories, regCfg.Content)

	var images []types.ImageReference

	if err = retry.RetryIfNecessary(context.Background(), func() error {
		images, err = imagesToCopyFromRepos(registryName, repos, srcCtx, regCfg.Content, log)
		return err
	}, retryOptions); err != nil {
		return err
	}

	if len(images) == 0 {
		log.Info().Msg("No images to copy, no need to sync")
		return nil
	}

	for _, ref := range images {
		imageRef := ref
		destSuffix := strings.Replace(ref.DockerReference().String(), registryName, "", 1)
		destination := fmt.Sprintf("//%s%s", destRegistry, destSuffix)

		destRef, err := docker.Transport.ParseReference(destination)
		if err != nil {
			return err
		}

		if err = retry.RetryIfNecessary(context.Background(), func() error {
			_, err = copy.Image(context.Background(), policyCtx, destRef, imageRef, &options)
			return err
		}, retryOptions); err != nil {
			return err
		}
	}

	log.Info().Msgf("Finished syncing %s", regCfg.URL)

	return nil
}

func copyDestCerts(serverCert, serverKey, caCert string) (string, error) {
	err := os.Mkdir(certsDir, 0755)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	if serverCert != "" {
		err := copyFile(serverCert, path.Join(certsDir, "server.cert"))
		if err != nil {
			return "", err
		}
	}

	if serverKey != "" {
		err := copyFile(serverKey, path.Join(certsDir, "server.key"))
		if err != nil {
			return "", err
		}
	}

	if caCert != "" {
		err := copyFile(caCert, path.Join(certsDir, "ca.crt"))
		if err != nil {
			return "", err
		}
	}

	return certsDir, nil
}

func getDestContexts(serverCert, serverKey,
	caCert string) (*types.SystemContext, *signature.PolicyContext, error) {
	var policy *signature.Policy

	var err error

	destCtx := &types.SystemContext{}

	if serverCert != "" && serverKey != "" {
		certsDir, err := copyDestCerts(serverCert, serverKey, caCert)
		if err != nil {
			return &types.SystemContext{}, &signature.PolicyContext{}, err
		}

		destCtx.DockerDaemonCertPath = certsDir
		destCtx.DockerCertPath = certsDir
		policy, err = signature.DefaultPolicy(destCtx)

		if err != nil {
			return &types.SystemContext{}, &signature.PolicyContext{}, err
		}
	} else {
		destCtx.DockerDaemonInsecureSkipTLSVerify = true
		destCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(true)
		policy = &signature.Policy{Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()}}
	}

	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		return &types.SystemContext{}, &signature.PolicyContext{}, err
	}

	return destCtx, policyContext, nil
}

func Run(cfg []RegistryConfig, log log.Logger, address, port, serverCert, serverKey, caCert string) error {
	destCtx, policyContext, err := getDestContexts(serverCert, serverKey, caCert)
	if err != nil {
		return err
	}

	destRegistry := fmt.Sprintf("%s:%s", address, port)

	var ticker *time.Ticker

	for _, regCfg := range cfg {
		// schedule each registry sync
		ticker = time.NewTicker(regCfg.PollInterval)

		go func(cfg RegistryConfig) {
			defer os.RemoveAll(certsDir)
			defer policyContext.Destroy() //nolint: errcheck
			// run sync first, then run on interval
			if err := syncRegistry(cfg, log, destRegistry, destCtx, policyContext); err != nil {
				log.Err(err).Msg("Sync exited with error, stopping it...")
				ticker.Stop()
			}

			// run on intervals
			for range ticker.C {
				if err := syncRegistry(cfg, log, destRegistry, destCtx, policyContext); err != nil {
					log.Err(err).Msg("Sync exited with error, stopping it...")
					ticker.Stop()
				}
			}
		}(regCfg)
	}

	log.Info().Msg("Finished setting up sync")

	return nil
}

func copyFile(sourceFilePath, destFilePath string) error {
	destFile, err := os.Create(destFilePath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	// should never get error because server certs are already handled by zot, by the time
	// it gets here
	sourceFile, _ := os.Open(sourceFilePath)
	defer sourceFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	return nil
}
