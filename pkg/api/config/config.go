package config

import (
	"github.com/anuvu/zot/errors"
	ext "github.com/anuvu/zot/pkg/extensions/config"
	"github.com/anuvu/zot/pkg/log"
	"github.com/containers/image/v5/types"
	"github.com/getlantern/deepcopy"
	dspec "github.com/opencontainers/distribution-spec"
)

// Global vars...
var (
	Commit     string // nolint: gochecknoglobals
	BinaryType string // nolint: gochecknoglobals
)

type StorageConfig struct {
	RootDirectory string
	GC            bool
	Dedupe        bool
}

type TLSConfig struct {
	Cert   string
	Key    string
	CACert string
}

type AuthHTPasswd struct {
	Path string
}

type AuthConfig struct {
	FailDelay int
	HTPasswd  AuthHTPasswd
	LDAP      *LDAPConfig
	Bearer    *BearerConfig
}

type BearerConfig struct {
	Realm   string
	Service string
	Cert    string
}

type HTTPConfig struct {
	Address         string
	Port            string
	TLS             *TLSConfig
	Auth            *AuthConfig
	Realm           string
	AllowReadAccess bool `mapstructure:",omitempty"`
	ReadOnly        bool `mapstructure:",omitempty"`
}

type LDAPConfig struct {
	Port          int
	Insecure      bool
	StartTLS      bool // if !Insecure, then StartTLS or LDAPs
	SkipVerify    bool
	SubtreeSearch bool
	Address       string
	BindDN        string
	BindPassword  string
	BaseDN        string
	UserAttribute string
	CACert        string
}

type LogConfig struct {
	Level  string
	Output string
	Audit  string
}

type GlobalStorageConfig struct {
	RootDirectory string
	Dedupe        bool
	GC            bool
	SubPaths      map[string]StorageConfig
}

type Config struct {
	Version    string
	Commit     string
	BinaryType string
	Storage    GlobalStorageConfig
	HTTP       HTTPConfig
	Log        *LogConfig
	Extensions *ext.ExtensionConfig
}

func New() *Config {
	return &Config{
		Version:    dspec.Version,
		Commit:     Commit,
		BinaryType: BinaryType,
		Storage:    GlobalStorageConfig{GC: true, Dedupe: true},
		HTTP:       HTTPConfig{Address: "127.0.0.1", Port: "8080"},
		Log:        &LogConfig{Level: "debug"},
	}
}

// Sanitize makes a sanitized copy of the config removing any secrets.
func (c *Config) Sanitize() *Config {
	s := &Config{}
	if err := deepcopy.Copy(s, c); err != nil {
		panic(err)
	}

	if c.HTTP.Auth != nil && c.HTTP.Auth.LDAP != nil && c.HTTP.Auth.LDAP.BindPassword != "" {
		s.HTTP.Auth.LDAP = &LDAPConfig{}

		if err := deepcopy.Copy(s.HTTP.Auth.LDAP, c.HTTP.Auth.LDAP); err != nil {
			panic(err)
		}

		s.HTTP.Auth.LDAP.BindPassword = "******"

		return s
	}

	if c.Extensions != nil && c.Extensions.Sync != nil {
		s.Extensions = &ext.ExtensionConfig{}

		if err := deepcopy.Copy(s.Extensions, c.Extensions); err != nil {
			panic(err)
		}

		regCfgs := *s.Extensions.Sync

		for id, regCfg := range *s.Extensions.Sync {
			if regCfg.Credentials != (types.DockerAuthConfig{}) {
				regCfg.Credentials.Password = "******"
			}

			regCfgs[id] = regCfg
		}

		s.Extensions.Sync = &regCfgs

		return s
	}

	return c
}

func (c *Config) Validate(log log.Logger) error {
	// LDAP configuration
	if c.HTTP.Auth != nil && c.HTTP.Auth.LDAP != nil {
		l := c.HTTP.Auth.LDAP
		if l.UserAttribute == "" {
			log.Error().Str("userAttribute", l.UserAttribute).Msg("invalid LDAP configuration")
			return errors.ErrLDAPConfig
		}
	}

	return nil
}
