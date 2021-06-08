// +build minimal

package extensions

import (
	"time"

	"github.com/anuvu/zot/pkg/api/config"
	extConf "github.com/anuvu/zot/pkg/extensions/config"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/mux"
)

// DownloadTrivyDB ...
func downloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
	return nil
}

// EnableExtensions ...
func EnableExtensions(extension *extConf.ExtensionConfig, log log.Logger, rootDir string, conf *config.Config) {
	log.Warn().Msg("skipping enabling extensions because given zot binary doesn't support any extensions, please build zot full binary for this feature")
}

// SetupRoutes ...
func SetupRoutes(extension *extConf.ExtensionConfig, router *mux.Router, storeController storage.StoreController, log log.Logger, conf *config.Config) {
	log.Warn().Msg("skipping setting up extensions routes because given zot binary doesn't support any extensions, please build zot full binary for this feature")
}
