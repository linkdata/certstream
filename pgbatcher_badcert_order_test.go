package certstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"

	"filippo.io/sunlight"
)

func TestRunBatchInsertsBadAndValidIdentitiesInOrder(t *testing.T) {
	ctx, db, cs, streamID, _ := cleanTestFixture(t)
	const auditSQL = `
CREATE TABLE CERTDB_test_ident_order (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization text NOT NULL,
  province text NOT NULL,
  country text NOT NULL
);
CREATE FUNCTION CERTDB_test_record_ident() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO CERTDB_test_ident_order (organization, province, country)
  VALUES (NEW.organization, NEW.province, NEW.country);
  RETURN NEW;
END;
$$;
CREATE TRIGGER CERTDB_test_record_ident AFTER INSERT ON CERTDB_ident
FOR EACH ROW EXECUTE FUNCTION CERTDB_test_record_ident();`
	if _, err := db.Exec(ctx, db.Pfx(auditSQL)); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
	makeEntry := func(index int64, der []byte, bad bool) *LogEntry {
		t.Helper()
		entry := ls.makeTileLogEntry(index, &sunlight.LogEntry{Certificate: der, Timestamp: now.UnixMilli()}, true)
		if bad && (entry.Err == nil || entry.Certificate != nil || len(entry.rawCert) == 0) {
			t.Fatalf("entry %d was not an unparseable certificate", index)
		}
		if !bad && (entry.Err != nil || entry.Certificate == nil) {
			t.Fatalf("entry %d was not a valid certificate: %v", index, entry.Err)
		}
		return entry
	}
	first := makeEntry(1, mismatchedSignatureAlgorithm(t, validOrderCert(t, "order-y", "order-z", now)), true)
	shard := db.workerIndexFor(first)
	var second, valid *LogEntry
	for attempt := 0; attempt < 1024 && second == nil; attempt++ {
		entry := makeEntry(2, mismatchedSignatureAlgorithm(t, validOrderCert(t, "order-a", "order-b", now)), true)
		if db.workerIndexFor(entry) == shard {
			second = entry
		}
	}
	for attempt := 0; attempt < 1024 && valid == nil; attempt++ {
		entry := makeEntry(3, validOrderCert(t, "order-n", "order-m", now), false)
		if db.workerIndexFor(entry) == shard {
			valid = entry
		}
	}
	if second == nil || valid == nil {
		t.Fatal("could not make bad and valid certificates for one SHA shard")
	}
	entries := []*LogEntry{
		first,
		second,
		valid,
	}
	for _, entry := range entries[:2] {
		hash := sha256.Sum256(entry.rawCert)
		if got, want := db.workerIndexFor(entry), int(hash[0]>>(8-db.workerBits)); got != want {
			t.Fatalf("bad certificate %d shard = %d, want raw SHA shard %d", entry.LogIndex, got, want)
		}
	}
	if err := db.runShardBatch(ctx, shard, entries); err != nil {
		t.Fatal(err)
	}
	var sequenceBefore int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT last_value FROM CERTDB_ident_id_seq`)).Scan(&sequenceBefore); err != nil {
		t.Fatal(err)
	}
	if err := db.runShardBatch(ctx, shard, entries); err != nil {
		t.Fatal(err)
	}
	var sequenceAfter int64
	if err := db.QueryRow(ctx, db.Pfx(`SELECT last_value FROM CERTDB_ident_id_seq`)).Scan(&sequenceAfter); err != nil {
		t.Fatal(err)
	}
	if sequenceAfter != sequenceBefore {
		t.Fatalf("identity sequence advanced on replay: %d to %d", sequenceBefore, sequenceAfter)
	}

	rows, err := db.Query(ctx, db.Pfx(`SELECT organization FROM CERTDB_test_ident_order ORDER BY seq`))
	if err != nil {
		t.Fatal(err)
	}
	var organizations []string
	for rows.Next() {
		var organization string
		if err := rows.Scan(&organization); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		organizations = append(organizations, organization)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if want := []string{"order-a", "order-b", "order-m", "order-n", "order-y", "order-z"}; !slices.Equal(organizations, want) {
		t.Fatalf("identity insertion order = %v, want %v", organizations, want)
	}
	var badCount, entryCount, markerCount int
	if err := db.QueryRow(ctx, db.Pfx(`SELECT count(*) FROM CERTDB_badcert WHERE stream = $1`), streamID).Scan(&badCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, db.Pfx(`SELECT count(*), count(*) FILTER (WHERE cert = 0)
FROM CERTDB_entry WHERE stream = $1`), streamID).Scan(&entryCount, &markerCount); err != nil {
		t.Fatal(err)
	}
	if badCount != 2 || entryCount != 3 || markerCount != 2 {
		t.Fatalf("stored badcerts=%d entries=%d markers=%d, want 2, 3, 2", badCount, entryCount, markerCount)
	}
}

func validOrderCert(t *testing.T, subject, issuer string, now time.Time) []byte {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{issuer},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{subject},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
