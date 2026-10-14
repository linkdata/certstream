package certstream

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

type gapLogRecord struct {
	message string
	fields  map[string]any
}

type gapLogCapture struct {
	mu      sync.Mutex
	records []gapLogRecord
}

func (l *gapLogCapture) Info(message string, args ...any) {
	fields := make(map[string]any, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		fields[args[i].(string)] = args[i+1]
	}
	l.mu.Lock()
	l.records = append(l.records, gapLogRecord{message, fields})
	l.mu.Unlock()
}

func (l *gapLogCapture) Error(message string, args ...any) { l.Info(message, args...) }

func (l *gapLogCapture) take() (records []gapLogRecord) {
	l.mu.Lock()
	records, l.records = l.records, nil
	l.mu.Unlock()
	return
}

func TestGapLogThresholdAndStreams(t *testing.T) {
	var logs gapLogCapture
	cdb := &PgDB{CertStream: &CertStream{Config: Config{Logger: &logs}}}
	first := &LogStream{Id: 1, log: &loglist3.Log{URL: "https://classic.example/"}}
	second := &LogStream{Id: 2, tiledLog: &loglist3.TiledLog{MonitoringURL: "https://tiled.example/"}}
	cdb.recordGap(first, gap{start: 10, end: 1009})
	if got := logs.take(); len(got) != 0 {
		t.Fatalf("1000-entry gap logged immediately: %v", got)
	}
	cdb.recordGap(first, gap{start: 1010, end: 2010})
	want := []gapLogRecord{{"certstream: gap", map[string]any{
		"url": first.URL(), "stream": first.Id, "logindex": int64(1010), "length": int64(1001),
	}}}
	if got := logs.take(); !reflect.DeepEqual(got, want) {
		t.Fatalf("immediate log = %v, want %v", got, want)
	}
	cdb.recordGap(second, gap{start: 3000, end: 3002})
	// A replacement reader for the same CT log contributes to the same summary.
	cdb.recordGap(&LogStream{Id: first.Id, log: first.log}, gap{start: 2011, end: 2011})
	cdb.logGaps()
	got := logs.take()
	slices.SortFunc(got, func(a, b gapLogRecord) int { return int(a.fields["stream"].(int32) - b.fields["stream"].(int32)) })
	want = []gapLogRecord{
		{"certstream: gaps", map[string]any{"url": first.URL(), "stream": first.Id, "gaps": int64(3), "entries": int64(2002)}},
		{"certstream: gaps", map[string]any{"url": second.URL(), "stream": second.Id, "gaps": int64(1), "entries": int64(3)}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summaries = %v, want %v", got, want)
	}
}

func TestGapLogReporter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs gapLogCapture
		cdb := &PgDB{CertStream: &CertStream{Config: Config{Logger: &logs}}}
		ls := &LogStream{Id: 1, log: &loglist3.Log{URL: "https://classic.example/"}}
		check := func(entries int64) {
			t.Helper()
			var want []gapLogRecord
			if entries > 0 {
				want = []gapLogRecord{{"certstream: gaps", map[string]any{
					"url": ls.URL(), "stream": ls.Id, "gaps": int64(1), "entries": entries,
				}}}
			}
			if got := logs.take(); !reflect.DeepEqual(got, want) {
				t.Fatalf("summaries = %v, want %v", got, want)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		var wg sync.WaitGroup
		wg.Add(1)
		go cdb.reportGaps(ctx, &wg)
		defer func() { cancel(); wg.Wait() }()
		synctest.Wait()
		cdb.recordGap(ls, gap{start: 20, end: 24})
		time.Sleep(time.Minute - time.Nanosecond)
		synctest.Wait()
		check(0)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		check(5)
		time.Sleep(time.Minute)
		synctest.Wait()
		check(0)
		cdb.recordGap(ls, gap{start: 30, end: 31})
		time.Sleep(time.Minute)
		synctest.Wait()
		check(2)
		cancel()
		wg.Wait()
		cdb.recordGap(ls, gap{start: 40, end: 42})
		time.Sleep(time.Minute)
		synctest.Wait()
		check(0)
		// Producers can finish after the reporter stops; shutdown flushes their counts.
		cdb.logGaps()
		check(3)
	})
}

func TestGapLogConcurrentFlush(t *testing.T) {
	var logs gapLogCapture
	cdb := &PgDB{CertStream: &CertStream{Config: Config{Logger: &logs}}}
	ls := &LogStream{Id: 1, log: &loglist3.Log{URL: "https://classic.example/"}}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				cdb.logGaps()
			}
		}
	}()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				cdb.recordGap(ls, gap{start: 10, end: 19})
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-done
	cdb.logGaps()
	var total int64
	for _, record := range logs.take() {
		count := record.fields["gaps"].(int64)
		if record.message != "certstream: gaps" || record.fields["stream"] != ls.Id || record.fields["url"] != ls.URL() || count <= 0 || record.fields["entries"] != count*10 {
			t.Fatalf("incoherent summary: %v", record)
		}
		total += count
	}
	if total != 4000 {
		t.Fatalf("total gaps = %d, want 4000", total)
	}
}
