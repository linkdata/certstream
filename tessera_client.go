package certstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/transparency-dev/formats/log"
	formatnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
)

const tesseraUserAgent = "certstream (+https://github.com/linkdata/certstream)"

var ErrTesseraClientMissing = errors.New("tessera client missing")

type tileFetchError struct {
	statusCode int
	url        string
	err        error
}

func (e tileFetchError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("get(%q): %d: %v", e.url, e.statusCode, e.err)
	}
	return fmt.Sprintf("get(%q): %d", e.url, e.statusCode)
}

func (e tileFetchError) Unwrap() error {
	return e.err
}

func (e tileFetchError) StatusCode() int {
	return e.statusCode
}

type tileClient struct {
	baseURL   *url.URL
	http      *http.Client
	userAgent string
	verifier  note.Verifier
	origin    string
}

func newTesseraClient(log *loglist3.TiledLog, httpClient *http.Client) (client *tileClient, err error) {
	var pub any
	if log != nil {
		originURL := log.MonitoringURL
		if log.SubmissionURL != "" {
			originURL = log.SubmissionURL
		}
		baseURLStr := log.MonitoringURL
		if baseURLStr == "" {
			baseURLStr = log.SubmissionURL
		}
		if pub, err = x509.ParsePKIXPublicKey(log.Key); err == nil {
			var vkey string
			if vkey, err = formatnote.RFC6962VerifierString(originURL, pub); err == nil {
				var verifier note.Verifier
				if verifier, err = formatnote.NewRFC6962Verifier(vkey); err == nil {
					var baseURL *url.URL
					if baseURL, err = url.Parse(baseURLStr); err == nil {
						client = &tileClient{
							baseURL:   baseURL,
							http:      httpClient,
							userAgent: tesseraUserAgent,
							verifier:  verifier,
							origin:    verifier.Name(),
						}
					}
				}
			}
		}
	}
	return
}

func (tc *tileClient) fetch(ctx context.Context, path string) ([]byte, error) {
	if tc == nil {
		return nil, ErrTesseraClientMissing
	}
	base := *tc.baseURL
	base.Path = strings.TrimSuffix(base.Path, "/") + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", tc.userAgent)
	client := tc.http
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return io.ReadAll(resp.Body)
	case http.StatusNotFound:
		return nil, tileFetchError{
			statusCode: resp.StatusCode,
			url:        base.String(),
			err:        os.ErrNotExist,
		}
	default:
		return nil, tileFetchError{
			statusCode: resp.StatusCode,
			url:        base.String(),
		}
	}
}

func (tc *tileClient) checkpoint(ctx context.Context) (*log.Checkpoint, []byte, error) {
	raw, err := tc.fetch(ctx, layout.CheckpointPath)
	if err != nil {
		return nil, nil, err
	}
	cp, _, _, err := log.ParseCheckpoint(raw, tc.origin, tc.verifier)
	if err != nil {
		return nil, nil, err
	}
	return cp, raw, nil
}

func (tc *tileClient) entryBundle(ctx context.Context, index uint64, logSize uint64) (api.EntryBundle, error) {
	p := layout.PartialTileSize(0, index, logSize)
	raw, err := tc.fetch(ctx, layout.EntriesPath(index, p))
	if err != nil && p > 0 && errors.Is(err, os.ErrNotExist) {
		raw, err = tc.fetch(ctx, layout.EntriesPath(index, 0))
	}
	if err != nil {
		return api.EntryBundle{}, err
	}
	var bundle api.EntryBundle
	if err := bundle.UnmarshalText(raw); err != nil {
		return api.EntryBundle{}, err
	}
	return bundle, nil
}
