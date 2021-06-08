// +build extended

package extensions

import (
	"github.com/anuvu/zot/pkg/api/config"
	extConf "github.com/anuvu/zot/pkg/extensions/config"
	"github.com/anuvu/zot/pkg/extensions/search"
	"github.com/anuvu/zot/pkg/extensions/sync"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/mux"

	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"

	"github.com/anuvu/zot/pkg/log"
)

// DownloadTrivyDB ...
func downloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
	for {
		log.Info().Msg("updating the CVE database")

		err := cveinfo.UpdateCVEDb(dbDir, log)
		if err != nil {
			return err
		}

		log.Info().Str("DB update completed, next update scheduled after", updateInterval.String()).Msg("")

		time.Sleep(updateInterval)
	}
}

func EnableExtensions(extension *extConf.ExtensionConfig, log log.Logger, rootDir string, config *config.Config) {
	if extension.Search != nil && extension.Search.Enable && extension.Search.CVE != nil {
		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if extension.Search.CVE.UpdateInterval < defaultUpdateInterval {
			extension.Search.CVE.UpdateInterval = defaultUpdateInterval

			log.Warn().Msg("CVE update interval set to too-short interval <= 1, changing update duration to 2 hours and continuing.") // nolint: lll
		}

		go func() {
			err := downloadTrivyDB(rootDir, log,
				extension.Search.CVE.UpdateInterval)
			if err != nil {
				log.Error().Err(err).Msg("error while downloading TrivyDB")
			}
		}()
	} else {
		log.Info().Msg("CVE config not provided, skipping CVE update")
	}

	if extension.Sync != nil {
		defaultPollInterval, _ := time.ParseDuration("1h")
		for _, registryCfg := range *extension.Sync {
			if registryCfg.PollInterval < defaultPollInterval {
				registryCfg.PollInterval = defaultPollInterval

				log.Warn().Msg("Sync registries interval set to too-short interval <= 1h, changing update duration to 1 hour and continuing.") // nolint: lll
			}
		}

		var serverCert string

		var serverKey string

		var CACert string

		if config.HTTP.TLS != nil {
			serverCert = config.HTTP.TLS.Cert
			serverKey = config.HTTP.TLS.Key
			CACert = config.HTTP.TLS.CACert
		}

		if err := sync.Run(*extension.Sync, log, config.HTTP.Address,
			config.HTTP.Port, serverCert, serverKey, CACert); err != nil {
			log.Error().Err(err).Msg("Error encountered while syncing")
		}
	} else {
		log.Info().Msg("Sync registries config not provided, skipping sync")
	}
}

// SetupRoutes ...
func SetupRoutes(extension *extConf.ExtensionConfig, router *mux.Router, storeController storage.StoreController,
	log log.Logger, config *config.Config) {
	log.Info().Msg("setting up extensions routes")

	if extension.Search != nil && extension.Search.Enable {
		resConfig := search.GetResolverConfig(log, storeController)
		router.PathPrefix("/query").Methods("GET", "POST").
			Handler(gqlHandler.NewDefaultServer(search.NewExecutableSchema(resConfig)))
	}

	var serverCert string

	var serverKey string

	var CACert string

	if config.HTTP.TLS != nil {
		serverCert = config.HTTP.TLS.Cert
		serverKey = config.HTTP.TLS.Key
		CACert = config.HTTP.TLS.CACert
	}

	if extension.Sync != nil {
		postSyncer := sync.PostHandler{
			Address:    config.HTTP.Address,
			Port:       config.HTTP.Port,
			ServerCert: serverCert,
			ServerKey:  serverKey,
			CACert:     CACert,
			Cfg:        *extension.Sync,
			Log:        log,
		}

		router.HandleFunc("/sync", postSyncer.Handler).Methods("POST")
	}
}
