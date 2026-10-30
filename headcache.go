package certstream

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type headPollCacheKey struct{}

type headPollCache struct {
	until time.Time
}

func withHeadPollCache(ctx context.Context, capture *headPollCache) context.Context {
	return context.WithValue(ctx, headPollCacheKey{}, capture)
}

type headCacheTransport struct {
	next http.RoundTripper
}

func (tr headCacheTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	resp, err = tr.next.RoundTrip(req)
	if capture, ok := req.Context().Value(headPollCacheKey{}).(*headPollCache); ok && err == nil && resp != nil && resp.StatusCode == http.StatusOK {
		now := time.Now()
		capture.until = now.Add(headFreshness(resp.Header, now))
	}
	return
}

func (capture *headPollCache) delay(defaultDelay time.Duration) time.Duration {
	if capture != nil {
		return max(defaultDelay, time.Until(capture.until))
	}
	return defaultDelay
}

func cacheSeconds(value string) (time.Duration, bool) {
	const maxSeconds = uint64((1<<63 - 1) / int64(time.Second))
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err != nil || seconds > maxSeconds {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func headFreshness(header http.Header, responseAt time.Time) time.Duration {
	var lifetime time.Duration
	hasMaxAge := false
	for _, line := range header.Values("Cache-Control") {
		for _, directive := range strings.Split(line, ",") {
			name, value, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-cache", "no-store":
				return 0
			case "max-age":
				if hasMaxAge {
					return 0
				}
				hasMaxAge = true
				value = strings.TrimSpace(value)
				if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
					value = value[1 : len(value)-1]
				}
				var ok bool
				if lifetime, ok = cacheSeconds(value); !ok {
					return 0
				}
			}
		}
	}

	date := responseAt
	if value := header.Get("Date"); value != "" {
		var err error
		if date, err = http.ParseTime(value); err != nil {
			return 0
		}
	}
	if !hasMaxAge {
		expires, err := http.ParseTime(header.Get("Expires"))
		if err != nil {
			return 0
		}
		lifetime = expires.Sub(date)
	}
	if lifetime <= 0 {
		return 0
	}

	age := time.Duration(0)
	if value := header.Get("Age"); value != "" {
		value, _, _ = strings.Cut(value, ",")
		var ok bool
		if age, ok = cacheSeconds(strings.TrimSpace(value)); !ok {
			return 0
		}
	}
	apparentAge := max(time.Duration(0), responseAt.Sub(date))
	if apparentAge >= lifetime || age >= lifetime {
		return 0
	}
	return lifetime - max(apparentAge, age)
}
