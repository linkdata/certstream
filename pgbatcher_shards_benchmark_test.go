package certstream

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

// BenchmarkPgDBRunGapBatchesByPrefix measures gap tile database writes.
//
// The mixed case measures one database call as a control. The prefix case uses
// the production grouping. Each iteration uses new hashes and log indexes;
// the sparse case places two entries in different prefixes of one 256-wide tile.
// Run with -benchtime=3x -count=6 when comparing batching changes.
func BenchmarkPgDBRunGapBatchesByPrefix(b *testing.B) {
	const tileSize = 256
	for _, tc := range []struct {
		name string
		size int
	}{
		{"two_entries", 2},
		{"full_tile", tileSize},
	} {
		for _, sharded := range []bool{false, true} {
			name := "mixed_one_call"
			if sharded {
				name = "prefix_batches"
			}
			b.Run(tc.name+"/"+name, func(b *testing.B) {
				ctx, db, cs, streamID, _ := cleanTestFixture(b)
				now := time.Now().UTC().Truncate(time.Second)
				der := makeTestCertificate(b, now)
				baseCert, err := ctx509.ParseCertificate(der)
				if err != nil {
					b.Fatal(err)
				}
				ls := &LogStream{LogOperator: &LogOperator{CertStream: cs}, Id: streamID}
				entries := make([]*LogEntry, tc.size)
				for i := range entries {
					cert := *baseCert
					cert.Subject.CommonName = "gap-" + strconv.Itoa(i) + ".example.test"
					entries[i] = &LogEntry{
						LogStream:   ls,
						Certificate: &cert,
						Signature:   make([]byte, sha256.Size),
						Seen:        now,
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				var totalBatches int
				for n := range b.N {
					b.StopTimer()
					var occupied [256]bool
					for i, entry := range entries {
						index := int64(n*tileSize + i*tileSize/tc.size)
						entry.LogIndex = index
						var seed [8]byte
						for nonce := uint64(index); ; nonce += 1 << 32 {
							binary.BigEndian.PutUint64(seed[:], nonce)
							sig := sha256.Sum256(seed[:])
							copy(entry.Signature, sig[:])
							if tc.size != 2 || i == 0 || db.workerIndexFor(entry) != db.workerIndexFor(entries[0]) {
								break
							}
						}
						occupied[db.workerIndexFor(entry)] = true
					}
					if sharded {
						for _, used := range occupied {
							if used {
								totalBatches++
							}
						}
					} else {
						totalBatches++
					}
					b.StartTimer()
					if sharded {
						stored, err := db.runGapBatches(ctx, entries)
						if err != nil {
							b.Fatal(err)
						}
						for _, ok := range stored {
							if !ok {
								b.Fatal("gap batch was not stored")
							}
						}
					} else if err := db.runBatch(ctx, entries); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				b.ReportMetric(float64(totalBatches)/float64(b.N), "db_batches/op")
			})
		}
	}
}
