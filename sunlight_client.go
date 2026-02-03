package certstream

import (
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/loglist3"
)

const sunlightUserAgent = "certstream (+https://github.com/linkdata/certstream)"

var ErrSunlightClientMissing = errors.New("sunlight client missing")

func newSunlightClient(log *loglist3.TiledLog, httpClient *http.Client, concurrency int) (client *sunlight.Client, err error) {
	var pub any
	if log != nil {
		if pub, err = x509.ParsePKIXPublicKey(log.Key); err == nil {
			cachedir := path.Join(os.TempDir(), "certstream")
			_ = os.RemoveAll(cachedir)
			if e := os.Mkdir(cachedir, 0755); e != nil {
				cachedir = ""
			}
			cfg := &sunlight.ClientConfig{
				MonitoringPrefix: log.MonitoringURL,
				PublicKey:        pub,
				HTTPClient:       httpClient,
				UserAgent:        sunlightUserAgent,
				ConcurrencyLimit: max(concurrency, 1),
				Cache:            cachedir,
			}
			client, err = sunlight.NewClient(cfg)
		}
	}
	return
}
