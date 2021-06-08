package sync

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	. "github.com/smartystreets/goconvey/convey"
)

const (
	BaseURL    = "http://127.0.0.1:5001"
	ServerCert = "../../../test/data/server.cert"
	ServerKey  = "../../../test/data/server.key"
	CACert     = "../../../test/data/ca.crt"

	testImage    = "zot-test"
	testImageTag = "0.0.1"

	host = "127.0.0.1:45117"
)

func TestSyncInternal(t *testing.T) {
	Convey("test parseRepositoryReference func", t, func() {
		repositoryReference := fmt.Sprintf("%s/%s", host, testImage)
		ref, err := parseRepositoryReference(repositoryReference)
		So(err, ShouldBeNil)
		So(ref.Name(), ShouldEqual, repositoryReference)

		repositoryReference = fmt.Sprintf("%s/%s:tagged", host, testImage)
		_, err = parseRepositoryReference(repositoryReference)
		So(err, ShouldEqual, errors.ErrInvalidRepositoryName)

		repositoryReference = fmt.Sprintf("http://%s/%s", host, testImage)
		_, err = parseRepositoryReference(repositoryReference)
		So(err, ShouldNotBeNil)

		repositoryReference = fmt.Sprintf("docker://%s/%s", host, testImage)
		_, err = parseRepositoryReference(repositoryReference)
		So(err, ShouldNotBeNil)

		srcCtx := &types.SystemContext{}
		_, err = getImageTags(context.Background(), srcCtx, ref)

		So(err, ShouldNotBeNil)

		_, _, err = getDestContexts("inexistent.cert", "inexistent.key", "inexistent.crt")
		So(err, ShouldNotBeNil)

		_, _, err = getDestContexts(ServerCert, "inexistent.key", "inexistent.crt")
		So(err, ShouldNotBeNil)

		_, _, err = getDestContexts(ServerCert, ServerKey, "inexistent.crt")
		So(err, ShouldNotBeNil)

		taggedRef, err := reference.WithTag(ref, testImageTag)
		So(err, ShouldBeNil)
		dockerRef, err := docker.NewReference(taggedRef)
		So(err, ShouldBeNil)

		So(getTagFromRef(dockerRef, log.NewLogger("", "")), ShouldNotBeNil)

		updateDuration := time.Microsecond
		syncRegistryConfig := RegistryConfig{
			Content: []Content{
				{
					Prefix: testImage,
				},
			},
			URL:          BaseURL,
			PollInterval: updateDuration,
			TLSVerify:    false,
			CertDir:      "",
		}

		So(Run([]RegistryConfig{syncRegistryConfig}, log.NewLogger("", ""),
			"127.0.0.1", "5000", ServerCert, ServerKey, CACert), ShouldBeNil)
	})
}
