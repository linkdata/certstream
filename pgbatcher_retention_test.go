package certstream

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/jackc/pgx/v5"
)

func retentionEntry(t *testing.T, ls *LogStream, index int64, expires time.Time) *LogEntry {
	t.Helper()
	der := makeTestCertificate(t, expires.Add(-time.Hour))
	cert, err := ctx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert.DNSNames = []string{"cert" + strconv.FormatInt(index, 10) + ".example.test"}
	sig := sha256.Sum256(der)
	return &LogEntry{
		LogStream:   ls,
		LogIndex:    index,
		Certificate: cert,
		Signature:   sig[:],
		Seen:        time.Now().UTC(),
	}
}

func TestPgDBRunBatchRetention(t *testing.T) {
	t.Parallel()
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	cutoff := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	callbackCount := 0
	cs.PgCertMaxAge = time.Hour
	cs.PgCertCutoff = func() time.Time {
		callbackCount++
		return cutoff
	}
	old := retentionEntry(t, ls, 1, cutoff.Add(-time.Second))
	boundary := retentionEntry(t, ls, 2, cutoff)
	newCert := retentionEntry(t, ls, 3, cutoff.Add(time.Second))
	if err := db.runBatch(ctx, []*LogEntry{old, boundary, newCert}); err != nil {
		t.Fatal(err)
	}
	if callbackCount != 1 {
		t.Fatalf("cutoff callback calls = %d, want 1", callbackCount)
	}
	var oldSeen time.Time
	if err := db.QueryRow(ctx, db.Pfx(`SELECT seen FROM CERTDB_entry WHERE stream = $1 AND logindex = 1`), streamID).Scan(&oldSeen); err != nil {
		t.Fatal(err)
	}
	if want := old.Seen.UTC().Truncate(time.Second); !oldSeen.Equal(want) {
		t.Fatalf("marker seen = %v, want %v", oldSeen, want)
	}

	// A skipped certificate gets a marker even when its hash already exists.
	cutoff = newCert.Certificate.NotAfter.Add(time.Second)
	replay := *newCert
	replay.LogIndex = 4
	if err := db.runBatch(ctx, []*LogEntry{&replay}); err != nil {
		t.Fatal(err)
	}
	if callbackCount != 2 {
		t.Fatalf("cutoff callback calls = %d, want 2", callbackCount)
	}

	// A zero callback result disables filtering even with PgCertMaxAge set.
	cutoff = time.Time{}
	replay = *old
	replay.LogIndex = 5
	if err := db.runBatch(ctx, []*LogEntry{&replay}); err != nil {
		t.Fatal(err)
	}
	if callbackCount != 3 {
		t.Fatalf("cutoff callback calls = %d, want 3", callbackCount)
	}

	// Without a callback, PgCertMaxAge supplies the cutoff.
	cs.PgCertCutoff = nil
	if err := db.runBatch(ctx, []*LogEntry{retentionEntry(t, ls, 6, time.Now().UTC().Add(-48*time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if callbackCount != 3 {
		t.Fatalf("cutoff callback calls = %d, want 3", callbackCount)
	}

	// A future callback cutoff cannot reject a currently valid certificate.
	cutoff = time.Now().UTC().Add(48 * time.Hour)
	cs.PgCertCutoff = func() time.Time {
		callbackCount++
		return cutoff
	}
	if err := db.runBatch(ctx, []*LogEntry{retentionEntry(t, ls, 7, time.Now().UTC().Add(24*time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if callbackCount != 4 {
		t.Fatalf("cutoff callback calls = %d, want 4", callbackCount)
	}

	// Both zero settings retain certificates regardless of expiration.
	cs.PgCertCutoff = nil
	cs.PgCertMaxAge = 0
	if err := db.runBatch(ctx, []*LogEntry{retentionEntry(t, ls, 8, time.Now().UTC().Add(-48*time.Hour))}); err != nil {
		t.Fatal(err)
	}

	// Marker-only batches bypass certificate ingest, tolerate duplicates, and preserve existing entries.
	cs.PgCertCutoff = func() time.Time { return cutoff }
	cutoff = newCert.Certificate.NotAfter.Add(time.Second)
	marker := retentionEntry(t, ls, 9, old.Certificate.NotAfter)
	marker.Seen = time.Time{}
	ingestQuery := db.funcIngestBatch
	db.funcIngestBatch = "SELECT 1/0"
	before := time.Now().UTC().Truncate(time.Second)
	if err := db.runBatch(ctx, []*LogEntry{marker, marker, newCert}); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC().Truncate(time.Second)
	db.funcIngestBatch = ingestQuery
	var markerSeen time.Time
	if err := db.QueryRow(ctx, db.Pfx(`SELECT seen FROM CERTDB_entry WHERE stream = $1 AND logindex = 9`), streamID).Scan(&markerSeen); err != nil {
		t.Fatal(err)
	}
	if markerSeen.Before(before) || markerSeen.After(after) {
		t.Fatalf("zero-seen marker = %v, want within [%v, %v]", markerSeen, before, after)
	}

	rows, err := db.Query(ctx, db.Pfx(`SELECT logindex, cert FROM CERTDB_entry WHERE stream = $1 ORDER BY logindex`), streamID)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[int64]int64)
	for rows.Next() {
		var index, certID int64
		if err := rows.Scan(&index, &certID); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		got[index] = certID
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if len(got) != 9 {
		t.Fatalf("stored indexes = %v, want 1 through 9", got)
	}
	for _, index := range []int64{1, 2, 4, 6, 9} {
		if got[index] != 0 {
			t.Errorf("index %d cert = %d, want marker 0", index, got[index])
		}
	}
	for _, index := range []int64{3, 5, 7, 8} {
		if got[index] == 0 {
			t.Errorf("index %d cert = 0, want stored certificate", index)
		}
	}
	if _, err := db.GetCertificateByLogEntry(ctx, &PgLogEntry{CertID: 0}); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("GetCertificateByLogEntry(marker) error = %v, want pgx.ErrNoRows", err)
	}
	var certs, domains int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT (SELECT count(*) FROM CERTDB_cert), (SELECT count(*) FROM CERTDB_domain)`)).Scan(&certs, &domains); err != nil {
		t.Fatal(err)
	}
	if certs != 4 || domains != 4 {
		t.Errorf("certificates/domains = %d/%d, want 4/4", certs, domains)
	}
	if gaps, err := db.storedGaps(ctx, streamID, 1, 9); err != nil {
		t.Fatal(err)
	} else if len(gaps) != 0 {
		t.Errorf("stored gaps = %v, want none", gaps)
	}
}

func TestPgDBRunBatchRetentionMixedRollback(t *testing.T) {
	t.Parallel()
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	cs.PgCertCutoff = func() time.Time { return time.Now().UTC().Add(-24 * time.Hour) }
	valid := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	missing := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: -1}
	retained := retentionEntry(t, valid, 1, time.Now().UTC().Add(24*time.Hour))
	marker := retentionEntry(t, missing, 2, time.Now().UTC().Add(-48*time.Hour))
	if err := db.runBatch(ctx, []*LogEntry{retained, marker}); err == nil {
		t.Fatal("mixed batch with invalid marker stream succeeded")
	}
	var certs, entries int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT (SELECT count(*) FROM CERTDB_cert), (SELECT count(*) FROM CERTDB_entry)`)).Scan(&certs, &entries); err != nil {
		t.Fatal(err)
	}
	if certs != 0 || entries != 0 {
		t.Fatalf("failed mixed batch committed %d certificates and %d entries", certs, entries)
	}
}
