package certstream

import "testing"

func TestOperatorDomain(t *testing.T) {
	tcs := []struct {
		in, want string
	}{
		{"https://googleapis.com/ct/logs", "googleapis.com"},
		{"https://www.googleapis.com/ct/v3", "googleapis.com"},
		{"http://letsencrypt.org/ct", "letsencrypt.org"},
		{"https://sub.operated.by.cloudflare.com/log", "cloudflare.com"},
		{"not a url", ""}, // invalid URL should give empty string
	}
	for _, tc := range tcs {
		if got := OperatorDomain(tc.in); got != tc.want {
			t.Fatalf("OperatorDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
