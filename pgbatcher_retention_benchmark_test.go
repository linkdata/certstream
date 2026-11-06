package certstream

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

// BenchmarkPgDBRunBatchRetention measures database batches at different expiry mixes.
//
// Each batch has 1,000 entries. Certificate data is prepared outside the timed
// section; each iteration uses new hashes and log indexes. Run with -benchtime=8x -count=6.
func BenchmarkPgDBRunBatchRetention(b *testing.B) {
	const batchSize = 1000
	for _, expired := range []int{0, batchSize / 2, batchSize} {
		b.Run(strconv.Itoa(expired)+"_expired", func(b *testing.B) {
			ctx, db, cs, streamID, _ := cleanTestFixture(b)
			cutoff := time.Now().UTC().Truncate(time.Second)
			cs.PgCertCutoff = func() time.Time { return cutoff }
			ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
			entries := make([]*LogEntry, batchSize)
			for i := range entries {
				expires := cutoff.Add(time.Hour)
				if i < expired {
					expires = cutoff.Add(-time.Hour)
				}
				der := makeTestCertificate(b, expires.Add(-time.Hour))
				cert, err := ctx509.ParseCertificate(der)
				if err != nil {
					b.Fatal(err)
				}
				name := "cert" + strconv.Itoa(i) + ".example.test"
				cert.Subject.CommonName = name
				cert.DNSNames = []string{name, "www." + name}
				sig := sha256.Sum256(der)
				entries[i] = &LogEntry{
					LogStream:   ls,
					Certificate: cert,
					Signature:   sig[:],
					Seen:        cutoff,
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for n := range b.N {
				b.StopTimer()
				for i, entry := range entries {
					entry.LogIndex = int64(n*batchSize + i)
					binary.BigEndian.PutUint64(entry.Signature[:8], uint64(n*batchSize+i))
				}
				b.StartTimer()
				if err := db.runBatch(ctx, entries); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
		})
	}
}
