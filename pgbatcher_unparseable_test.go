package certstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"filippo.io/sunlight"
)

func mismatchedSignatureAlgorithm(t *testing.T, der []byte) []byte {
	t.Helper()
	oid := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02} // ecdsa-with-SHA256
	if got := bytes.Count(der, oid); got != 2 {
		t.Fatalf("signature algorithm OID occurs %d times, want 2", got)
	}
	der = bytes.Clone(der)
	der[bytes.LastIndex(der, oid)+len(oid)-1] = 0x03 // ecdsa-with-SHA384 in outer field
	return der
}

func TestUnparseableCertificatesCloseGaps(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	if err := insertEntries(ctx, db, streamID, []int64{0, 2, 4}); err != nil {
		t.Fatal(err)
	}
	cs.mu.Lock()
	cs.sendEntryCh = make(chan *LogEntry, 5)
	cs.mu.Unlock()
	workerCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go db.worker(workerCtx, &wg, 0)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	now := time.Now().UTC().Truncate(time.Millisecond)
	classic := makeTestLeafEntry(t, now)
	classic.LeafInput = mismatchedSignatureAlgorithm(t, classic.LeafInput)
	entries := []*LogEntry{
		ls.makeLogEntry(1, classic, true),
		ls.makeTileLogEntry(3, &sunlight.LogEntry{
			Certificate: mismatchedSignatureAlgorithm(t, makeTestCertificate(t, now)),
			Timestamp:   now.UnixMilli(),
		}, true),
		ls.makeTileLogEntry(5, &sunlight.LogEntry{
			Certificate: []byte{0x30, 0x00},
			Timestamp:   now.UnixMilli(),
		}, true),
	}
	var secondStreamID int32
	if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_stream (url, operator, json)
SELECT 'https://example.com/second-log', operator, '{}' FROM CERTDB_stream WHERE id = $1 RETURNING id`), streamID).Scan(&secondStreamID); err != nil {
		t.Fatal(err)
	}
	duplicate := *entries[0]
	duplicate.LogStream = &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: secondStreamID}
	duplicate.LogIndex = 1
	entries = append(entries, &duplicate)
	entries = append(entries, duplicate.makeTileLogEntry(2, &sunlight.LogEntry{
		Certificate: []byte{},
		Timestamp:   now.UnixMilli(),
	}, true))
	for _, le := range entries {
		if le.Err == nil || le.Certificate != nil || le.rawCert == nil {
			t.Fatalf("entry %d = (certificate %v, err %v), want parse error", le.LogIndex, le.Certificate, le.Err)
		}
		if !le.sendEntry(ctx, now, le) {
			t.Fatalf("entry %d was not handled", le.LogIndex)
		}
	}
	for range 2 {
		ack := make(chan struct{}, 1)
		select {
		case db.batchCh[0] <- &LogEntry{flushAck: ack}:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		select {
		case <-ack:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	select {
	case le := <-cs.getSendEntryCh():
		t.Fatalf("unparseable entry published to consumers: %v", le)
	default:
	}
	for _, le := range entries {
		var certID int64
		var seen time.Time
		if err := db.QueryRow(ctx, db.Pfx(`SELECT cert, seen FROM CERTDB_entry WHERE stream = $1 AND logindex = $2`), le.LogStream.Id, le.LogIndex).Scan(&certID, &seen); err != nil {
			t.Fatal(err)
		}
		if certID != 0 || !seen.Equal(now.Truncate(time.Second)) {
			t.Fatalf("entry %d = (cert %d, seen %v), want marker at %v", le.LogIndex, certID, seen, now.Truncate(time.Second))
		}
		var name string
		var badSeen time.Time
		var subject, issuer [3]string
		var hash, raw []byte
		if err := db.QueryRow(ctx, db.Pfx(`SELECT b.seen, b.commonname, sub.organization, sub.province, sub.country,
iss.organization, iss.province, iss.country, b.sha256, b.rawcert
FROM CERTDB_badcert b
JOIN CERTDB_ident sub ON sub.id = b.subject
JOIN CERTDB_ident iss ON iss.id = b.issuer
WHERE b.stream = $1 AND b.logindex = $2`), le.LogStream.Id, le.LogIndex).Scan(
			&badSeen, &name, &subject[0], &subject[1], &subject[2], &issuer[0], &issuer[1], &issuer[2], &hash, &raw,
		); err != nil {
			t.Fatal(err)
		}
		wantHash := sha256.Sum256(le.rawCert)
		wantName := "example.test"
		if (le.LogStream.Id == streamID && le.LogIndex == 5) || len(le.rawCert) == 0 {
			wantName = ""
		}
		if !badSeen.Equal(seen) || name != wantName || subject != ([3]string{}) || issuer != ([3]string{}) || !bytes.Equal(hash, wantHash[:]) || !bytes.Equal(raw, le.rawCert) {
			t.Fatalf("badcert %d = (seen %v, name %q, subject %v, issuer %v, hash %x, raw length %d)", le.LogIndex, badSeen, name, subject, issuer, hash, len(raw))
		}
	}
	var sightings int
	hash := sha256.Sum256(entries[0].rawCert)
	if err := db.QueryRow(ctx, db.Pfx(`SELECT count(*) FROM CERTDB_badcert WHERE sha256 = $1`), hash[:]).Scan(&sightings); err != nil {
		t.Fatal(err)
	}
	if sightings != 2 {
		t.Fatalf("duplicate certificate sightings = %d, want 2", sightings)
	}
	if gaps, err := db.storedGaps(ctx, streamID, 0, 5); err != nil {
		t.Fatal(err)
	} else if len(gaps) != 0 {
		t.Fatalf("stored gaps = %v, want none", gaps)
	}
	ls.gapCh = make(chan gap, 1)
	if err := db.selectStreamGaps(ctx, ls); err != nil {
		t.Fatal(err)
	}
	var cursor int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1`), streamID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 5 {
		t.Fatalf("backfill_logindex = %d, want 5", cursor)
	}
}

func TestBadCertInsertFailureLeavesGap(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	leaf := makeTestLeafEntry(t, time.Now().UTC())
	leaf.LeafInput = mismatchedSignatureAlgorithm(t, leaf.LeafInput)
	le := ls.makeLogEntry(1, leaf, true)
	if le.Err == nil || len(le.rawCert) == 0 {
		t.Fatalf("entry = (err %v, raw length %d), want unparseable certificate", le.Err, len(le.rawCert))
	}
	if _, err := db.Exec(ctx, db.Pfx(`DROP TABLE CERTDB_badcert`)); err != nil {
		t.Fatal(err)
	}
	withoutRaw := *le
	withoutRaw.LogIndex = 2
	withoutRaw.rawCert = nil
	if err := db.runBatch(ctx, []*LogEntry{&withoutRaw}); err != nil {
		t.Fatal(err)
	}
	if err := db.runBatch(ctx, []*LogEntry{le}); err == nil {
		t.Fatal("batch succeeded without badcert table")
	}
	var failedStored, noRawStored bool
	if err := db.QueryRow(ctx, db.Pfx(`SELECT
EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 1),
EXISTS(SELECT 1 FROM CERTDB_entry WHERE stream = $1 AND logindex = 2)`), streamID).Scan(&failedStored, &noRawStored); err != nil {
		t.Fatal(err)
	}
	if failedStored || !noRawStored {
		t.Fatalf("gap markers = (failed insert %v, no raw bytes %v), want (false, true)", failedStored, noRawStored)
	}
}

func TestBadCertStoresRecoveredIdentities(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	raw, err := os.ReadFile("testdata/hetu2027-8925345.der")
	if err != nil {
		t.Fatal(err)
	}
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	le := &LogEntry{LogStream: ls, LogIndex: 1, Err: errors.New("unparseable certificate"), rawCert: raw}
	valid := retentionEntry(t, ls, 2, time.Now().UTC().Add(24*time.Hour))
	if err := db.runBatch(ctx, []*LogEntry{le, valid}); err != nil {
		t.Fatal(err)
	}
	var certID int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT cert FROM CERTDB_entry WHERE stream = $1 AND logindex = 2`), streamID).Scan(&certID); err != nil {
		t.Fatal(err)
	}
	if certID == 0 {
		t.Fatal("mixed batch skipped the parseable certificate")
	}
	var name, subOrg, subCountry, issOrg, issCountry string
	if err := db.QueryRow(ctx, db.Pfx(`SELECT b.commonname, sub.organization, sub.country, iss.organization, iss.country
FROM CERTDB_badcert b
JOIN CERTDB_ident sub ON sub.id = b.subject
JOIN CERTDB_ident iss ON iss.id = b.issuer
WHERE b.stream = $1 AND b.logindex = 1`), streamID).Scan(&name, &subOrg, &subCountry, &issOrg, &issCountry); err != nil {
		t.Fatal(err)
	}
	if name != "Encryption Everywhere DV TLS CA - G1" || subOrg != "DigiCert Inc" || subCountry != "US" || issOrg != "DigiCert Inc" || issCountry != "US" {
		t.Fatalf("recovered metadata = (%q, %q, %q, %q, %q)", name, subOrg, subCountry, issOrg, issCountry)
	}
}

func TestBadTiledPrecertStoresTBS(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	tbs := []byte{0x30, 0x00}
	le := ls.makeTileLogEntry(1, &sunlight.LogEntry{
		IsPrecert:   true,
		Certificate: tbs,
		Timestamp:   time.Now().UTC().UnixMilli(),
	}, true)
	if le.Err == nil || le.rawCert == nil {
		t.Fatalf("precertificate = (err %v, raw %x), want unparseable TBS", le.Err, le.rawCert)
	}
	if err := db.runBatch(ctx, []*LogEntry{le}); err != nil {
		t.Fatal(err)
	}
	var storedRaw, hash []byte
	if err := db.QueryRow(ctx, db.Pfx(`SELECT rawcert, sha256 FROM CERTDB_badcert WHERE stream = $1 AND logindex = 1`), streamID).Scan(&storedRaw, &hash); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(tbs)
	if !bytes.Equal(storedRaw, tbs) || !bytes.Equal(hash, wantHash[:]) {
		t.Fatalf("bad precertificate = (raw %x, hash %x), want (%x, %x)", storedRaw, hash, tbs, wantHash)
	}
}
