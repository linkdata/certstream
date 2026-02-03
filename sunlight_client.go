package certstream

import (
	"crypto/x509"
	"errors"
	"net/http"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/loglist3"
)

const sunlightUserAgent = "certstream (+https://github.com/linkdata/certstream)"

var ErrSunlightClientMissing = errors.New("sunlight client missing")

func newSunlightClient(log *loglist3.TiledLog, httpClient *http.Client, concurrency int) (client *sunlight.Client, err error) {
	var pub any
	if log != nil {
		if pub, err = x509.ParsePKIXPublicKey(log.Key); err == nil {
			cfg := &sunlight.ClientConfig{
				MonitoringPrefix: log.MonitoringURL,
				PublicKey:        pub,
				HTTPClient:       httpClient,
				UserAgent:        sunlightUserAgent,
				ConcurrencyLimit: max(concurrency, 1),
			}
			client, err = sunlight.NewClient(cfg)
		}
	}
	return
}
