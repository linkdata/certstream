package certstream

import (
	"net"
	"os"
	"path"
	"time"

	"golang.org/x/net/proxy"
)

type Config struct {
	Logger       Logger              // if not nil Logger to use, no default
	HeadDialer   proxy.ContextDialer // dialer for following the head, defaults to &net.Dialer{}
	HeadLog      string              // log HTTP requests using the head dialer to this file
	TailDialer   proxy.ContextDialer // if not nil, backfill db using this dialer, no default
	PgUser       string              // PostgreSQL user, default "certstream"
	PgPass       string              // PostgreSQL password, default "certstream"
	PgName       string              // PostgreSQL db name, default "certstream"
	PgAddr       string              // PostgreSQL address, no default
	PgPrefix     string              // PostgreSQL naming prefix, default "certdb_"
	PgConns      int                 // max number of database connections, default 100
	PgWorkerBits int                 // number of prefix bits that determine DB workers, default 5 (32 workers)
	PgMaxAge     int                 // maximum age in days to backfill
	PgNoSSL      bool                // if true, do not use SSL
	PgSyncCommit bool                // if true, do not set synchronous_commit=off
	Concurrency  int                 // number of concurrent requests per stream, default is 4
	CacheDir     string              // cache directory; set to "none" to disable
	CacheMaxAge  time.Duration       // remove cache files older than this age; zero disables
	TailLog      string              // log HTTP requests using the tail dialer to this file
}

// NewConfig returns a new default Config
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
		CacheDir:     path.Join(os.TempDir(), "certstream"),
		CacheMaxAge:  time.Hour,
	}
}
