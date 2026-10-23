package certstream

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

func TestRetiredRefreshDrainsWorkersAndRetries(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "retry", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	base, err := loglist3.NewFromJSON([]byte(sampleLogData))
	if err != nil {
		t.Fatal(err)
	}
	retiredLog := *base.Operators[0].Logs[1]
	retiredLog.URL = server.URL + "/retired/"
	activeLog := *base.Operators[0].Logs[2]
	activeLog.URL = server.URL + "/active/"
	activeLog.State = &loglist3.LogStates{Usable: &loglist3.LogState{Timestamp: time.Now()}}
	list := &loglist3.LogList{IsAllLogs: true, Operators: []*loglist3.Operator{{Name: "Test", Email: []string{"test@example.com"}, Logs: []*loglist3.Log{&retiredLog, &activeLog}}}}
	setList := func() {
		t.Helper()
		data, err := json.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		cs.HeadClient = &http.Client{Transport: testLogListTransport{RoundTripper: server.Client().Transport, list: data}}
	}
	cs.mu.Lock()
	cs.sendEntryCh = make(chan *LogEntry, 8)
	cs.mu.Unlock()
	var workerWG, streamWG sync.WaitGroup
	workerCtx, stopWorkers := context.WithCancel(ctx)
	workerWG.Add(1)
	go db.runWorkers(workerCtx, &workerWG)
	t.Cleanup(func() {
		stopWorkers()
		streamWG.Wait()
		workerWG.Wait()
	})
	var calls [][]int32
	cs.OnRetiredStreams = func(_ context.Context, db *PgDB, ids []int32) error {
		calls = append(calls, append([]int32(nil), ids...))
		for _, id := range ids {
			var count int
			if err := db.QueryRow(ctx, db.Pfx(`SELECT COUNT(*) FROM CERTDB_entry WHERE stream = $1`), id).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				t.Errorf("retired stream %d has %d committed entries at cleanup", id, count)
			}
		}
		return nil
	}
	setList()
	streamWG.Add(1)
	if err := cs.updateStreams(ctx, &streamWG); err != nil {
		t.Fatal(err)
	}
	var old, active *LogStream
	for _, op := range cs.Operators() {
		for _, ls := range op.Streams() {
			switch ls.URL() {
			case retiredLog.URL:
				old = ls
			case activeLog.URL:
				active = ls
			}
		}
	}
	if old == nil || active == nil {
		t.Fatal("both usable readers must start")
	}
	der := makeTestCertificate(t, time.Now())
	cert, err := ctx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sig := sha256.Sum256(der)
	for _, ls := range []*LogStream{old, active} {
		db.sendToBatcher(ctx, &LogEntry{LogStream: ls, Certificate: cert, Signature: sig[:], Seen: time.Now(), LogIndex: 1})
	}
	select {
	case <-old.done:
		t.Fatal("reader stopped before retirement refresh")
	default:
	}
	retiredLog.State = &loglist3.LogStates{Retired: &loglist3.LogState{Timestamp: time.Now()}}
	// A local cache error for another usable log must not hold retired rows.
	cs.DataDir = t.TempDir()
	blockedURL := server.URL + "/blocked/"
	if err := os.MkdirAll(getCacheDir(cs.DataDir, ""), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(getCacheDir(cs.DataDir, blockedURL), []byte("blocked"), 0o644); err != nil {
		t.Fatal(err)
	}
	list.Operators[0].TiledLogs = []*loglist3.TiledLog{{
		MonitoringURL: blockedURL,
		Key:           activeLog.Key,
		State:         &loglist3.LogStates{Usable: &loglist3.LogState{Timestamp: time.Now()}},
	}}
	setList()
	streamWG.Add(1)
	if err := cs.updateStreams(ctx, &streamWG); err == nil {
		t.Fatal("cache setup error was not reported")
	}
	list.Operators[0].TiledLogs = nil
	if len(calls) != 1 || len(calls[0]) != 1 || calls[0][0] != old.Id {
		t.Fatalf("retired callback = %v, want stream %d", calls, old.Id)
	}
	checkStoredState := func(want loglist3.LogStatus) {
		t.Helper()
		var data string
		if err := db.QueryRow(ctx, db.Pfx(`SELECT json FROM CERTDB_stream WHERE id = $1`), old.Id).Scan(&data); err != nil {
			t.Fatal(err)
		}
		var stored loglist3.Log
		if err := json.Unmarshal([]byte(data), &stored); err != nil {
			t.Fatal(err)
		}
		if stored.State.LogStatus() != want || stored.URL != retiredLog.URL || stored.Description != retiredLog.Description {
			t.Fatalf("stored stream state = %s, url = %q, description = %q; want %s and unchanged metadata", stored.State.LogStatus(), stored.URL, stored.Description, want)
		}
	}
	checkStoredState(loglist3.RetiredLogStatus)
	select {
	case <-old.done:
	default:
		t.Fatal("retired producer still running at callback")
	}
	var activeCount int
	if err := db.QueryRow(ctx, db.Pfx(`SELECT COUNT(*) FROM CERTDB_entry WHERE stream = $1`), active.Id).Scan(&activeCount); err != nil || activeCount != 1 {
		t.Fatalf("active batch entry count = %d, err = %v", activeCount, err)
	}
	list.Operators = nil
	setList()
	streamWG.Add(1)
	if err := cs.updateStreams(ctx, &streamWG); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[1][0] != old.Id {
		t.Fatalf("absent retired stream was not retried: %v", calls)
	}
	checkStoredState(loglist3.RetiredLogStatus)
	retiredLog.State = &loglist3.LogStates{ReadOnly: &loglist3.ReadOnlyLogState{LogState: loglist3.LogState{Timestamp: time.Now()}}}
	list.Operators = []*loglist3.Operator{{Name: "Test", Email: []string{"test@example.com"}, Logs: []*loglist3.Log{&retiredLog}}}
	setList()
	streamWG.Add(1)
	if err := cs.updateStreams(ctx, &streamWG); err != nil {
		t.Fatal(err)
	}
	checkStoredState(loglist3.ReadOnlyLogStatus)
	if len(calls) != 2 {
		t.Fatalf("read-only transition invoked cleanup: %v", calls)
	}
}

type blockedReaderTransport struct{}

func (blockedReaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestStreamRegistrationSurvivesConcurrentLastReaderRemoval(t *testing.T) {
	ctx, db, cs := setupSelectGapsDB(t)
	cs.DataDir = ""
	cs.HeadClient = &http.Client{Transport: blockedReaderTransport{}}
	op := &loglist3.Operator{Name: "Test", Email: []string{"test@example.com"}}
	base, err := loglist3.NewFromJSON([]byte(sampleLogData))
	if err != nil {
		t.Fatal(err)
	}
	newLog := *base.Operators[0].Logs[1]
	newLog.URL = "https://logs.example.com/new/"
	oldLog := *base.Operators[0].Logs[1]
	oldLog.URL = "https://logs.example.com/old/"
	lo := &LogOperator{CertStream: cs, operator: op, Domain: OperatorDomain(newLog.URL), streams: map[string]*LogStream{}}
	if err := db.ensureOperator(ctx, lo); err != nil {
		t.Fatal(err)
	}
	old := &LogStream{LogOperator: lo, log: &oldLog}
	lo.streams[old.URL()] = old
	cs.operators[lo.Domain] = lo
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, db.Pfx(`LOCK TABLE CERTDB_stream IN ACCESS EXCLUSIVE MODE`)); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	var streamWG sync.WaitGroup
	t.Cleanup(func() { cancel(); streamWG.Wait() })
	registerDone := make(chan error, 1)
	go func() { registerDone <- cs.ensureOperatorAndLog(runCtx, op, &newLog, &streamWG) }()
	deadline := time.Now().Add(5 * time.Second)
	for db.Stat().AcquiredConns() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if db.Stat().AcquiredConns() < 2 {
		t.Fatal("new stream did not reach blocked database setup")
	}
	removeDone := make(chan struct{})
	go func() { cs.removeStream(old); close(removeDone) }()
	select {
	case <-removeDone:
		t.Fatal("last reader removed operator during new stream setup")
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-registerDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-removeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("old reader removal stayed blocked")
	}
	cs.mu.Lock()
	current := cs.operators[lo.Domain]
	cs.mu.Unlock()
	if current != lo || current.streams[newLog.URL] == nil {
		t.Fatal("new reader became invisible after old reader removal")
	}
}
