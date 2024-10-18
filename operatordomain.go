package certstream

import (
	"net/url"
	"strings"
)

// OperatorDomain returns the TLD+1 given an URL.
func OperatorDomain(urlString string) string {
	opDom := urlString
	if u, err := url.Parse(urlString); err == nil {
		opDom = u.Host
		if idx := strings.LastIndexByte(opDom, ':'); idx > 0 {
			opDom = opDom[:idx]
		}
		if idx := strings.LastIndexByte(opDom, '.'); idx > 0 {
			if idx := strings.LastIndexByte(opDom[:idx], '.'); idx > 0 {
				opDom = opDom[idx+1:]
			}
		}
	}
	return opDom
}
