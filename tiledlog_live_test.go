package certstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestLiveStaticTiledLogs(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	logList, err := getLogList(ctx, http.DefaultClient, loglist3.AllLogListURL)
	if err != nil {
		t.Fatalf("getLogList: %v", err)
	}

	var tiledLogs []*loglist3.TiledLog
	for _, op := range logList.Operators {
		for _, log := range op.TiledLogs {
			if log == nil || log.MonitoringURL == "" || len(log.Key) == 0 {
				continue
			}
			tiledLogs = append(tiledLogs, log)
		}
	}
	if len(tiledLogs) == 0 {
		t.Fatalf("log list contains no tiled logs")
	}

	const maxAttempts = 10
	attempts := 0
	var failures []string

	for _, log := range tiledLogs {
		if attempts >= maxAttempts {
			break
		}
		attempts++

		logCtx, logCancel := context.WithTimeout(ctx, 20*time.Second)
		err := func() error {
			defer logCancel()

			client, err := newTesseraClient(log, http.DefaultClient)
			if err != nil {
				return err
			}
			checkpoint, _, err := client.checkpoint(logCtx)
			if err != nil {
				return err
			}
			if checkpoint.Size == 0 {
				return fmt.Errorf("checkpoint has zero size")
			}

			return nil
		}()
		if err == nil {
			return
		}
		failures = append(failures, log.Description+": "+err.Error())
	}

	t.Fatalf("no live tiled logs passed; failures: %v", failures)
}

func TestLiveLetsEncryptTiledLogLastEntry(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	logList, err := getLogList(ctx, http.DefaultClient, loglist3.AllLogListURL)
	if err != nil {
		t.Fatalf("getLogList: %v", err)
	}

	var leLogs []*loglist3.TiledLog
	for _, op := range logList.Operators {
		if op == nil || op.Name != "Let's Encrypt" {
			continue
		}
		for _, log := range op.TiledLogs {
			if log == nil || log.MonitoringURL == "" || len(log.Key) == 0 {
				continue
			}
			leLogs = append(leLogs, log)
		}
	}
	if len(leLogs) == 0 {
		t.Fatalf("no Let's Encrypt tiled log found")
	}

	var failures []string
	for i := len(leLogs) - 1; i >= 0; i-- {
		log := leLogs[i]
		le, err := fetchLastLogEntry(ctx, log)
		if err != nil {
			failures = append(failures, log.Description+": "+err.Error())
			continue
		}
		if le == nil {
			failures = append(failures, log.Description+": missing log entry")
			continue
		}
		if le.Err != nil {
			failures = append(failures, log.Description+": "+le.Err.Error())
			continue
		}
		if le.Certificate == nil {
			failures = append(failures, log.Description+": missing parsed certificate")
			continue
		}
		return
	}

	if len(failures) == 0 {
		t.Fatalf("no usable Let's Encrypt tiled log found")
	}
	t.Skipf("no usable Let's Encrypt tiled log found: %v", failures)
}

func fetchLastLogEntry(ctx context.Context, log *loglist3.TiledLog) (*LogEntry, error) {
	le, err := fetchLastLogEntryWithClient(ctx, log)
	if err == nil {
		return le, nil
	}
	var fetchErr tileFetchError
	if errors.As(err, &fetchErr) && fetchErr.StatusCode() == http.StatusForbidden && log.SubmissionURL != "" {
		fallback := *log
		fallback.MonitoringURL = ""
		return fetchLastLogEntryWithClient(ctx, &fallback)
	}
	return nil, err
}

func fetchLastLogEntryWithClient(ctx context.Context, log *loglist3.TiledLog) (*LogEntry, error) {
	client, err := newTesseraClient(log, http.DefaultClient)
	if err != nil {
		return nil, err
	}
	checkpoint, _, err := client.checkpoint(ctx)
	if err != nil {
		return nil, err
	}
	if checkpoint.Size == 0 {
		return nil, fmt.Errorf("checkpoint has zero size")
	}

	lastIndex := int64(checkpoint.Size - 1)
	entryData, err := (&tileEntryCache{}).entryAt(ctx, client, uint64(lastIndex), checkpoint.Size)
	if err != nil {
		return nil, err
	}
	entry, err := parseTileEntry(entryData)
	if err != nil {
		return nil, err
	}
	return (&LogStream{}).makeTileLogEntry(lastIndex, entry, false), nil
}
