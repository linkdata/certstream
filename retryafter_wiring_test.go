package certstream

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func retryAfterWiringClient(calls *atomic.Int64) *http.Client {
	return &http.Client{Transport: retryAfterRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return retryAfterResponse(http.StatusTooManyRequests, "1"), nil
	})}
}

func checkProviderWiringCooldown(t *testing.T, calls *atomic.Int64, first, second func(context.Context) error) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		if err := first(ctx); err == nil {
			t.Fatal("first provider call succeeded; want 429 error")
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("first provider network calls = %d; want 1", got)
		}
		ctx, cancel = context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		if err := second(ctx); err == nil {
			t.Fatal("second provider call succeeded during cooldown")
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("provider network calls during cooldown = %d; want 1", got)
		}
	})
}

func TestMakeStreamWiresRetryAfter(t *testing.T) {
	var headCalls, tailCalls atomic.Int64
	cs := &CertStream{
		HeadClient: retryAfterWiringClient(&headCalls),
		TailClient: retryAfterWiringClient(&tailCalls),
	}
	lo := &LogOperator{CertStream: cs}
	ls, err := lo.makeStream(&loglist3.Log{URL: "https://example.com/ct"})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("head", func(t *testing.T) {
		fetch := func(ctx context.Context) error {
			_, err := ls.headClient.GetSTH(ctx)
			return err
		}
		checkProviderWiringCooldown(t, &headCalls, fetch, fetch)
	})
	t.Run("tail", func(t *testing.T) {
		fetch := func(ctx context.Context) error {
			_, err := ls.tailClient.GetRawEntries(ctx, 0, 255)
			return err
		}
		checkProviderWiringCooldown(t, &tailCalls, fetch, fetch)
	})
}

func TestMakeTiledStreamWiresRetryAfter(t *testing.T) {
	var headCalls, tailCalls atomic.Int64
	cs := &CertStream{
		Config:     Config{TailDialer: &net.Dialer{}},
		HeadClient: retryAfterWiringClient(&headCalls),
		TailClient: retryAfterWiringClient(&tailCalls),
	}
	lo := &LogOperator{CertStream: cs}
	ls, err := lo.makeTiledStream(newTestTiledLog(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("head checkpoint", func(t *testing.T) {
		fetch := func(ctx context.Context) error {
			_, err := ls.headTile.TileReader().ReadEndpoint(ctx, "checkpoint")
			return err
		}
		checkProviderWiringCooldown(t, &headCalls, fetch, fetch)
	})
	t.Run("tail and gap tiles", func(t *testing.T) {
		first := func(ctx context.Context) error {
			_, err := ls.tailTile.TileReader().ReadEndpoint(ctx, "tile/data/1")
			return err
		}
		second := func(ctx context.Context) error {
			_, err := ls.gapTile.TileReader().ReadEndpoint(ctx, "tile/data/2")
			return err
		}
		checkProviderWiringCooldown(t, &tailCalls, first, second)
	})
}
