package certstream

import (
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/loglist3"
)

const sunlightUserAgent = "certstream (+https://github.com/linkdata/certstream)"

var ErrSunlightClientMissing = errors.New("sunlight client missing")

func newSunlightClient(log *loglist3.TiledLog, httpClient *http.Client, logger *slog.Logger, concurrency int, cacheDir string) (client *sunlight.Client, err error) {
	var pub any
	if cacheDir != "" {
		err = os.MkdirAll(cacheDir, 0o755)
	}
	if err == nil {
		if log != nil {
			if pub, err = x509.ParsePKIXPublicKey(log.Key); err == nil {
				cfg := &sunlight.ClientConfig{
					MonitoringPrefix: log.MonitoringURL,
					PublicKey:        pub,
					HTTPClient:       httpClient,
					UserAgent:        sunlightUserAgent,
					ConcurrencyLimit: max(concurrency, 1),
					Cache:            cacheDir,
					Logger:           logger,
				}
				client, err = sunlight.NewClient(cfg)
			}
		}
	}
	return
}
