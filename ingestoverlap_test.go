package certstream_test

import (
	"fmt"
	"testing"
	"time"
)

func TestIngestBatch_SinceOverlapBoundaries(t *testing.T) {
	ctx, conn, streamID := setupIngestBatchTest(t)
	year := func(n int) time.Time { return time.Date(n, 1, 1, 0, 0, 0, 0, time.UTC) }
	type cert struct {
		before, after int
		precert       bool
	}
	tests := []struct {
		name            string
		prior           []cert
		target          cert
		wantSince       int
		priorSince      int
		emptyCommonName bool
	}{
		{"no overlap", []cert{{2020, 2021, false}}, cert{2022, 2023, false}, 2022, 0, false},
		{"older long-lived overlap", []cert{{2020, 2025, false}, {2021, 2022, false}}, cert{2023, 2026, false}, 2020, 0, false},
		{"opposite precert only", []cert{{2020, 2025, false}}, cert{2022, 2026, true}, 2022, 0, false},
		{"newer opposite precert", []cert{{2020, 2025, false}, {2021, 2026, true}}, cert{2022, 2027, false}, 2020, 0, false},
		{"inclusive expiry", []cert{{2020, 2022, false}}, cert{2022, 2026, false}, 2020, 0, false},
		{"strict notbefore", []cert{{2022, 2025, false}}, cert{2022, 2026, false}, 2022, 2020, false},
		{"empty common name", []cert{{2020, 2025, false}}, cert{2022, 2026, false}, 2022, 0, true},
		{"ordinary overlap", []cert{{2020, 2025, false}}, cert{2022, 2026, false}, 2020, 0, false},
	}
	seen := year(2024)
	logIndex := int64(0)
	for caseIndex, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			commonName := fmt.Sprintf("case-%d.example.com", caseIndex)
			if tc.emptyCommonName {
				commonName = ""
			}
			add := func(c cert) string {
				logIndex++
				sha := fmt.Sprintf("%064x", logIndex)
				row := ingestRowWithSHA(streamID, logIndex, commonName, seen, sha)
				row["commonname"] = commonName
				row["notbefore"] = year(c.before)
				row["notafter"] = year(c.after)
				row["precert"] = c.precert
				if err := callIngestBatch(ctx, conn, row); err != nil {
					t.Fatalf("ingest certificate %s: %v", sha, err)
				}
				return sha
			}
			for _, c := range tc.prior {
				sha := add(c)
				if tc.priorSince != 0 {
					// Earlier since exposes an accidental match at equal notbefore.
					tag, err := conn.Exec(ctx, "UPDATE CERTDB_cert SET since = $1 WHERE sha256 = decode($2, 'hex')", year(tc.priorSince), sha)
					if err != nil {
						t.Fatalf("set prior since: %v", err)
					}
					if tag.RowsAffected() != 1 {
						t.Fatalf("set prior since affected %d rows, want 1", tag.RowsAffected())
					}
				}
			}
			sha := add(tc.target)
			since, err := certSince(ctx, conn, sha)
			if err != nil {
				t.Fatal(err)
			}
			if want := year(tc.wantSince); !since.Equal(want) {
				t.Errorf("since = %s, want %s", since, want)
			}
		})
	}
}
