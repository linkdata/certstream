package certstream

import (
	"net"

	"golang.org/x/net/proxy"
)

type Config struct {
	Logger                Logger              // if not nil Logger to use, no default
	HeadDialer            proxy.ContextDialer // dialer for following the head, defaults to &net.Dialer{}
	TailDialer            proxy.ContextDialer // if not nil, backfill db using this dialer, no default
	PgUser                string              // PostgreSQL user, default "certstream"
	PgPass                string              // PostgreSQL password, default "certstream"
	PgName                string              // PostgreSQL db name, default "certstream"
	PgAddr                string              // PostgreSQL address, no default
	PgPrefix              string              // PostgreSQL naming prefix, default "certdb_"
	PgConns               int                 // max number of database connections, default 100
	PgMaxAge              int                 // maximum age in days to backfill
	PgNoSSL               bool                // if true, do not use SSL
	GetEntriesParallelism int                 // number of concurrent GetRawEntries requests per range, default 8
}

// NewConfig returns a new default Config
func NewConfig() *Config {
	return &Config{
		Logger:                nil,
		HeadDialer:            &net.Dialer{},
		TailDialer:            nil,
		PgUser:                "certstream",
		PgPass:                "certstream",
		PgName:                "certstream",
		PgAddr:                "",
		PgPrefix:              "certdb_",
		PgConns:               100,
		PgMaxAge:              90,
		GetEntriesParallelism: 8,
	}
}
