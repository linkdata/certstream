package certstream

import (
	"context"
	"net"
	"os"
	"path"
	"time"

	"golang.org/x/net/proxy"
)

// Config controls CT streaming and optional persistence.
type Config struct {
	Logger           Logger                                      // if not nil Logger to use, no default
	HeadDialer       proxy.ContextDialer                         // dialer for following the head, defaults to &net.Dialer{}
	HeadLog          string                                      // log HTTP requests using the head dialer to this file
	TailDialer       proxy.ContextDialer                         // if not nil, backfill db using this dialer, no default
	PgUser           string                                      // PostgreSQL user, default "certstream"
	PgPass           string                                      // PostgreSQL password, default "certstream"
	PgName           string                                      // PostgreSQL db name, default "certstream"
	PgAddr           string                                      // PostgreSQL address, no default
	PgPrefix         string                                      // PostgreSQL naming prefix, default "certdb_"
	PgConns          int                                         // max number of database connections, default 100
	PgWorkerBits     int                                         // number of prefix bits that determine DB workers, default 5 (32 workers)
	PgMaxAge         int                                         // maximum age in days to backfill
	PgCertMaxAge     time.Duration                               // cleanup delay after expiry; also sets ingest cutoff when PgCertCutoff is nil; zero disables cleanup
	PgNoSSL          bool                                        // if true, do not use SSL
	PgSyncCommit     bool                                        // if true, do not set synchronous_commit=off
	Concurrency      int                                         // number of concurrent requests per stream, default is 4
	DataDir          string                                      // log and cache directory; leave empty to disable
	CacheMaxAge      time.Duration                               // remove cached tile data older than this age; zero disables caching of tiles
	TailLog          string                                      // log HTTP requests using the tail dialer to this file
	OnRetiredStreams func(context.Context, *PgDB, []int32) error // nil disables callback; invoked for retired database rows after readers stop if queued database writes succeed

	// ProviderConcurrency overrides Concurrency for matching CT log providers.
	//
	// Keys are [OperatorDomain] values for CT log URLs. A nil map or non-positive
	// entries use Concurrency. The limit applies separately to each classic head
	// reader and tiled head, tail, and gap client. It does not cap total provider
	// requests. [Start] copies the input map before streaming. The map on the
	// returned [CertStream] is a startup snapshot; do not mutate it while
	// streaming. Use [CertStream.SetProviderConcurrency] to change limits.
	ProviderConcurrency map[string]int

	// PgCertCutoff returns the expiration cutoff for ingestion.
	//
	// Certificates with NotAfter at or before the cutoff keep only CT index
	// markers. Marked entries are not refetched if the cutoff later moves earlier.
	// The callback runs once per database batch and may run concurrently.
	// A zero time disables filtering; nil uses PgCertMaxAge. Future cutoffs are
	// capped at batch time. [Start] copies the callback; keep the copy on
	// [CertStream] unchanged while streaming.
	PgCertCutoff func() time.Time
}

// NewConfig returns a Config with default values.
func NewConfig() *Config {
	return &Config{
		Logger:       nil,
		HeadDialer:   &net.Dialer{},
		TailDialer:   nil,
		PgUser:       "certstream",
		PgPass:       "certstream",
		PgName:       "certstream",
		PgAddr:       "",
		PgPrefix:     "certdb_",
		PgConns:      100,
		PgWorkerBits: 5,
		PgMaxAge:     90,
		Concurrency:  4,
		DataDir:      path.Join(os.TempDir(), "certstream"),
		CacheMaxAge:  time.Minute * 10,
	}
}
