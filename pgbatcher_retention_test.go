package certstream

import (
	"crypto/sha256"
	"encoding/json"
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

func TestLogEntryAppendJSONRetention(t *testing.T) {
	t.Parallel()
	expires := time.Now().UTC().Truncate(time.Second)
	le := retentionEntry(t, &LogStream{Id: 7}, 11, expires)
	for _, tc := range []struct {
		name    string
		cutoff  time.Time
		skipped bool
	}{
		{"zero cutoff", time.Time{}, false},
		{"before expiry", expires.Add(-time.Nanosecond), false},
		{"at expiry", expires, true},
		{"after expiry", expires.Add(time.Nanosecond), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var row map[string]json.RawMessage
			if err := json.Unmarshal(le.appendJSON(nil, tc.cutoff), &row); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"notbefore", "notafter", "sha256_hex", "seen", "stream", "logindex", "dnsnames"} {
				if _, ok := row[key]; !ok {
					t.Errorf("missing %s", key)
				}
			}
			_, skipped := row["store_cert"]
			if skipped != tc.skipped {
				t.Errorf("store_cert present = %t, want %t", skipped, tc.skipped)
			}
		})
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
	if len(got) != 8 {
		t.Fatalf("stored indexes = %v, want 1 through 8", got)
	}
	for _, index := range []int64{1, 2, 4, 6} {
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
	if gaps, err := db.storedGaps(ctx, streamID, 1, 8); err != nil {
		t.Fatal(err)
	} else if len(gaps) != 0 {
		t.Errorf("stored gaps = %v, want none", gaps)
	}
}
