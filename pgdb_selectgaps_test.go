package certstream

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/linkdata/certstream/internal/testpg"
)

func TestPgDB_SelectStreamGapsUpdatesBackfillIndexOnNoGaps(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-no-gaps"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else if err = insertEntries(ctx, db, streamID, []int64{1, 2, 3, 4, 5}); err != nil {
				t.Fatalf("insert entries failed: %v", err)
			} else {
				logop := &LogOperator{
					CertStream: cs,
					operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
					Domain:     "example.com",
					streams:    map[string]*LogStream{},
				}
				ls := &LogStream{
					LogOperator: logop,
					Id:          streamID,
					log:         &loglist3.Log{URL: url},
				}
				ls.gapCh = make(chan gap, 1)
				logop.streams[url] = ls
				cs.operators = map[string]*LogOperator{
					logop.Domain: logop,
				}

				var wg sync.WaitGroup
				var scanErr error
				wg.Go(func() { scanErr = db.selectStreamGaps(ctx, ls) })

				wg.Wait()
				if scanErr != nil {
					t.Fatal(scanErr)
				}

				var backfillIndex int64
				if err = db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1;`),
					streamID,
				).Scan(&backfillIndex); err != nil {
					t.Fatalf("select backfill_logindex failed: %v", err)
				} else if backfillIndex != 5 {
					t.Fatalf("backfill_logindex = %d, want %d", backfillIndex, 5)
				}
				if got := ls.GapScanIndex.Load(); got != 0 {
					t.Fatalf("GapScanIndex = %d, want 0 without a cold sweep", got)
				}
			}
		}
	}
}

func TestPgDB_SelectStreamGapsClosesGapCh(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-close-gapch"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else if err = insertEntries(ctx, db, streamID, []int64{1, 3}); err != nil {
				t.Fatalf("insert entries failed: %v", err)
			} else {
				logop := &LogOperator{
					CertStream: cs,
					operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
					Domain:     "example.com",
					streams:    map[string]*LogStream{},
				}
				ls := &LogStream{
					LogOperator: logop,
					Id:          streamID,
					log:         &loglist3.Log{URL: url},
				}
				ls.gapCh = make(chan gap, 1)
				logop.streams[url] = ls
				cs.operators = map[string]*LogOperator{
					logop.Domain: logop,
				}

				if err = db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
					t.Fatalf("set backfill index failed: %v", err)
				} else {
					var wg sync.WaitGroup
					var scanErr error
					wg.Go(func() { scanErr = db.selectStreamGaps(ctx, ls) })

					wg.Wait()
					if scanErr != nil {
						t.Fatal(scanErr)
					}

					gapCh := ls.getGapCh()
					if gapCh == nil {
						t.Fatalf("gap channel not initialized")
					} else {
						gotCh := make(chan []gap, 1)
						go func() {
							gotCh <- collectGaps(gapCh)
						}()
						select {
						case got := <-gotCh:
							want := []gap{{start: 2, end: 2}}
							if !gapsEqual(got, want) {
								t.Fatalf("gaps = %v, want %v", got, want)
							}
						case <-time.After(2 * time.Second):
							t.Fatalf("gap channel not closed")
						}
					}
				}
			}
		}
	}
}

func TestPgDB_SelectStreamGapsExample(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-example"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else if err = insertEntries(ctx, db, streamID, []int64{1, 3, 6, 8}); err != nil {
				t.Fatalf("insert entries failed: %v", err)
			} else {
				logop := &LogOperator{
					CertStream: cs,
					operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
					Domain:     "example.com",
					streams:    map[string]*LogStream{},
				}
				ls := &LogStream{
					LogOperator: logop,
					Id:          streamID,
					log:         &loglist3.Log{URL: url},
				}
				ls.gapCh = make(chan gap, 4)
				logop.streams[url] = ls
				cs.operators = map[string]*LogOperator{
					logop.Domain: logop,
				}

				if err = db.backfillSetGapStartIndex(ctx, ls, 1); err != nil {
					t.Fatalf("set backfill index failed: %v", err)
				} else {
					var wg sync.WaitGroup
					var scanErr error
					wg.Go(func() { scanErr = db.selectStreamGaps(ctx, ls) })

					wg.Wait()
					if scanErr != nil {
						t.Fatal(scanErr)
					}
					got := collectGaps(ls.gapCh)
					want := []gap{
						{start: 2, end: 2},
						{start: 4, end: 5},
						{start: 7, end: 7},
					}
					if !gapsEqual(got, want) {
						t.Fatalf("gaps = %v, want %v", got, want)
					}
				}
			}
		}
	}
}

func TestPgDB_SelectStreamGapsOrder(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-order"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else {
				if err = insertEntries(ctx, db, streamID, []int64{1, 2, 4, 7, 8, 11}); err != nil {
					t.Fatalf("insert entries failed: %v", err)
				} else {
					logop := &LogOperator{
						CertStream: cs,
						operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
						Domain:     "example.com",
						streams:    map[string]*LogStream{},
					}
					ls := &LogStream{
						LogOperator: logop,
						Id:          streamID,
						log:         &loglist3.Log{URL: url},
					}
					ls.gapCh = make(chan gap, 1)
					logop.streams[url] = ls
					cs.operators = map[string]*LogOperator{
						logop.Domain: logop,
					}

					addGapQuerySleep(t, db, "0.2")

					var wg sync.WaitGroup
					gotCh := make(chan []gap, 1)
					go func() {
						time.Sleep(300 * time.Millisecond)
						gotCh <- collectGaps(ls.gapCh)
					}()

					var scanErr error
					wg.Go(func() { scanErr = db.selectStreamGaps(ctx, ls) })

					wg.Wait()
					if scanErr != nil {
						t.Fatal(scanErr)
					}
					got := <-gotCh
					want := []gap{
						{start: 3, end: 3},
						{start: 5, end: 6},
						{start: 9, end: 10},
					}
					if !gapsEqual(got, want) {
						t.Fatalf("gaps = %v, want %v", got, want)
					}
				}
			}
		}
	}
}

func TestPgDB_SelectStreamGapsMaxAtStart(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-max-at-start"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else {
				if err = insertEntries(ctx, db, streamID, []int64{1, 2, 4, 7, 8, 11}); err != nil {
					t.Fatalf("insert entries failed: %v", err)
				} else {
					logop := &LogOperator{
						CertStream: cs,
						operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
						Domain:     "example.com",
						streams:    map[string]*LogStream{},
					}
					ls := &LogStream{
						LogOperator: logop,
						Id:          streamID,
						log:         &loglist3.Log{URL: url},
					}
					ls.gapCh = make(chan gap, 10)
					logop.streams[url] = ls
					cs.operators = map[string]*LogOperator{
						logop.Domain: logop,
					}

					addGapQuerySleep(t, db, "0.2")

					firstGapCh := make(chan gap, 1)
					gotCh := make(chan []gap, 1)
					go func() {
						var got []gap
						for g := range ls.gapCh {
							if len(got) == 0 {
								firstGapCh <- g
							}
							got = append(got, g)
						}
						gotCh <- got
					}()

					var wg sync.WaitGroup
					var scanErr error
					wg.Go(func() { scanErr = db.selectStreamGaps(ctx, ls) })

					select {
					case <-firstGapCh:
						if err = insertEntries(ctx, db, streamID, []int64{20}); err != nil {
							t.Fatalf("insert entries after start failed: %v", err)
						} else {
							wg.Wait()
							if scanErr != nil {
								t.Fatal(scanErr)
							}
							got := <-gotCh
							want := []gap{
								{start: 3, end: 3},
								{start: 5, end: 6},
								{start: 9, end: 10},
							}
							if !gapsEqual(got, want) {
								t.Fatalf("gaps = %v, want %v", got, want)
							}
						}
					case <-time.After(2 * time.Second):
						t.Fatalf("timed out waiting for first gap")
					}
				}
			}
		}
	}
}

func TestPgDB_SelectStreamGapsUsesBackfillIndex(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-backfill-start"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else if err = insertEntries(ctx, db, streamID, []int64{1, 2, 4, 6}); err != nil {
				t.Fatalf("insert entries failed: %v", err)
			} else {
				logop := &LogOperator{
					CertStream: cs,
					operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
					Domain:     "example.com",
					streams:    map[string]*LogStream{},
				}
				ls := &LogStream{
					LogOperator: logop,
					Id:          streamID,
					log:         &loglist3.Log{URL: url},
				}
				ls.gapCh = make(chan gap, 2)
				logop.streams[url] = ls
				cs.operators = map[string]*LogOperator{
					logop.Domain: logop,
				}

				if err = db.backfillSetGapStartIndex(ctx, ls, 4); err != nil {
					t.Fatalf("set backfill index failed: %v", err)
				} else {
					var wg sync.WaitGroup
					var scanErr error
					wg.Go(func() { scanErr = db.selectStreamGaps(ctx, ls) })

					wg.Wait()
					if scanErr != nil {
						t.Fatal(scanErr)
					}
					got := collectGaps(ls.gapCh)
					want := []gap{
						{start: 3, end: 3},
						{start: 5, end: 5},
					}
					if !gapsEqual(got, want) {
						t.Fatalf("gaps = %v, want %v", got, want)
					}
				}
			}
		}
	}
}

func TestPgDB_SelectStreamGapsKeepsLeadingGapBeforeBackfillIndex(t *testing.T) {
	t.Parallel()

	ctx, db, cs := setupSelectGapsDB(t)
	if db != nil && cs != nil {
		var operatorID int32
		if err := db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_operator (name, email) VALUES ($1, $2) RETURNING id;`),
			"op", "op@example.com",
		).Scan(&operatorID); err != nil {
			t.Fatalf("insert operator failed: %v", err)
		} else {
			url := "https://example.com/log-leading-gap"
			var streamID int32
			if err = insertStream(ctx, db, url, operatorID, &streamID); err != nil {
				t.Fatalf("insert stream failed: %v", err)
			} else if err = insertEntries(ctx, db, streamID, []int64{1, 2, 5, 6}); err != nil {
				t.Fatalf("insert entries failed: %v", err)
			} else {
				logop := &LogOperator{
					CertStream: cs,
					operator:   &loglist3.Operator{Name: "op", Email: []string{"op@example.com"}},
					Domain:     "example.com",
					streams:    map[string]*LogStream{},
				}
				ls := &LogStream{
					LogOperator: logop,
					Id:          streamID,
					log:         &loglist3.Log{URL: url},
				}
				ls.gapCh = make(chan gap, 2)
				logop.streams[url] = ls
				cs.operators = map[string]*LogOperator{
					logop.Domain: logop,
				}

				if err = db.backfillSetGapStartIndex(ctx, ls, 3); err != nil {
					t.Fatalf("set backfill index failed: %v", err)
				} else {
					var wg sync.WaitGroup
					var scanErr error
					wg.Go(func() { scanErr = db.selectStreamGaps(ctx, ls) })

					wg.Wait()
					if scanErr != nil {
						t.Fatal(scanErr)
					}
					got := collectGaps(ls.gapCh)
					want := []gap{
						{start: 3, end: 4},
					}
					if !gapsEqual(got, want) {
						t.Fatalf("gaps = %v, want %v", got, want)
					} else {
						var backfillIndex int64
						if err = db.QueryRow(ctx, db.Pfx(`SELECT backfill_logindex FROM CERTDB_stream WHERE id = $1;`),
							streamID,
						).Scan(&backfillIndex); err != nil {
							t.Fatalf("select backfill_logindex failed: %v", err)
						} else if backfillIndex != 3 {
							t.Fatalf("backfill_logindex = %d, want %d", backfillIndex, 3)
						}
					}
				}
			}
		}
	}
}

func setupSelectGapsDB(t testing.TB) (ctx context.Context, db *PgDB, cs *CertStream) {
	t.Helper()
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(t.Context(), 3*time.Minute)
	t.Cleanup(cancel)
	fixture := testpg.NewDatabase(ctx, t)
	cfg := NewConfig()
	cfg.PgUser = testpg.User
	cfg.PgPass = testpg.Password
	cfg.PgName = fixture.Name
	cfg.PgAddr = fixture.Addr
	cfg.PgNoSSL = true
	cfg.PgConns = 4
	cs = &CertStream{
		Config:    *cfg,
		operators: map[string]*LogOperator{},
	}
	var err error
	if db, err = NewPgDB(ctx, cs); err != nil {
		t.Fatalf("NewPgDB failed: %v", err)
	}
	cs.db = db
	t.Cleanup(db.Close)
	return
}

func insertStream(ctx context.Context, db *PgDB, url string, operatorID int32, streamID *int32) (err error) {
	if streamID != nil {
		err = db.QueryRow(ctx, db.Pfx(`INSERT INTO CERTDB_stream (url, operator, json) VALUES ($1, $2, $3) RETURNING id;`),
			url, operatorID, "{}",
		).Scan(streamID)
	}
	return
}

func insertEntries(ctx context.Context, db *PgDB, streamID int32, indices []int64) (err error) {
	for _, logIndex := range indices {
		if err == nil {
			_, err = db.Exec(ctx, db.Pfx(`INSERT INTO CERTDB_entry (cert, logindex, stream) VALUES ($1, $2, $3);`),
				logIndex+1000, logIndex, streamID,
			)
		}
	}
	return
}

func addGapQuerySleep(t testing.TB, db *PgDB, seconds string) {
	t.Helper()

	if db == nil {
		t.Fatalf("db is nil")
	} else {
		gapWindowFrom := "FROM " + db.Pfx("CERTDB_entry")
		if !strings.Contains(db.stmtSelectGapWindow, gapWindowFrom) {
			t.Fatalf("selectStreamGaps missing %s", gapWindowFrom)
		} else {
			db.stmtSelectGapWindow = "WITH gap_sleep AS MATERIALIZED (SELECT pg_sleep(" + seconds + "))\n" + db.stmtSelectGapWindow
			db.stmtSelectGapWindow = strings.Replace(db.stmtSelectGapWindow,
				gapWindowFrom,
				"FROM gap_sleep, "+db.Pfx("CERTDB_entry"),
				1,
			)
		}
	}
}

func collectGaps(ch chan gap) (gaps []gap) {
	if ch != nil {
		for g := range ch {
			gaps = append(gaps, g)
		}
	}
	return
}

func gapsEqual(got []gap, want []gap) (equal bool) {
	if len(got) == len(want) {
		equal = true
		for i := range got {
			if got[i] != want[i] {
				equal = false
				break
			}
		}
	}
	return
}
