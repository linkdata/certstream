package certstream

import (
	"net"

	"golang.org/x/net/proxy"
)

type Config struct {
	Logger     Logger              // if not nil Logger to use, no default
	HeadDialer proxy.ContextDialer // dialer for following the head, defaults to &net.Dialer{}
	TailDialer proxy.ContextDialer // if not nil, backfill db using this dialer, no default
}

// NewConfig returns a new default Config
func NewConfig() *Config {
	return &Config{
		Logger:     nil,
		HeadDialer: &net.Dialer{},
		TailDialer: nil,
	}
}
