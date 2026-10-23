package certstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/google/certificate-transparency-go/loglist3"
)

func (cs *CertStream) ensureOperator(ctx context.Context, op *loglist3.Operator, opDom string) (logop *LogOperator, err error) {
	cs.mu.Lock()
	logop = cs.operators[opDom]
	cs.mu.Unlock()

	if logop == nil {
		logop = &LogOperator{
			CertStream: cs,
			operator:   op,
			Domain:     opDom,
			streams:    make(map[string]*LogStream),
		}
		sort.Strings(op.Email)
		if err = cs.DB().ensureOperator(ctx, logop); err == nil {
			cs.mu.Lock()
			cs.operators[opDom] = logop
			cs.mu.Unlock()
		}
	}
	return
}

func (cs *CertStream) ensureOperatorAndLog(ctx context.Context, op *loglist3.Operator, log *loglist3.Log, wg *sync.WaitGroup) (err error) {
	cs.lifecycleMu.Lock()
	defer cs.lifecycleMu.Unlock()
	opDom := OperatorDomain(log.URL)

	var logop *LogOperator
	if logop, err = cs.ensureOperator(ctx, op, opDom); err == nil {
		err = logop.ensureStream(ctx, log, wg)
	}

	return
}

func (cs *CertStream) ensureOperatorAndTiledLog(ctx context.Context, op *loglist3.Operator, log *loglist3.TiledLog, wg *sync.WaitGroup) (err error) {
	cs.lifecycleMu.Lock()
	defer cs.lifecycleMu.Unlock()
	opDom := OperatorDomain(log.MonitoringURL)

	var logop *LogOperator
	if logop, err = cs.ensureOperator(ctx, op, opDom); err == nil {
		err = logop.ensureTiledStream(ctx, log, wg)
	}

	return
}

func (cs *CertStream) updateStreams(ctx context.Context, wg *sync.WaitGroup) (err error) {
	defer wg.Done()
	if ctx.Err() == nil {
		var logList *loglist3.LogList
		if logList, err = getLogList(ctx, cs.HeadClient, loglist3.AllLogListURL); err == nil {
			states := make(map[string]*loglist3.LogStates)
			addState := func(url string, state *loglist3.LogStates) bool {
				status := state.LogStatus()
				if status == loglist3.RetiredLogStatus {
					if prior, ok := states[url]; ok && prior.LogStatus() != loglist3.RetiredLogStatus {
						return false
					}
				}
				states[url] = state
				return status == loglist3.UsableLogStatus
			}
			for _, op := range logList.Operators {
				for _, log := range op.Logs {
					if addState(log.URL, log.State) {
						if e := cs.ensureOperatorAndLog(ctx, op, log, wg); e != nil {
							err = errors.Join(err, e)
						}
					}
				}
				for _, log := range op.TiledLogs {
					if addState(log.MonitoringURL, log.State) {
						if e := cs.ensureOperatorAndTiledLog(ctx, op, log, wg); e != nil {
							err = errors.Join(err, e)
						}
					}
				}
			}
			if ctx.Err() == nil {
				retired := make(map[string]bool)
				for url, state := range states {
					if state.LogStatus() == loglist3.RetiredLogStatus {
						retired[url] = true
					}
				}
				_ = cs.LogError(cs.retireStreams(ctx, retired, states), "retireStreams")
			}
		}

		var operators []string
		for _, lo := range cs.Operators() {
			operators = append(operators, fmt.Sprintf("%s*%d", lo.Domain, len(lo.Streams())))
		}
		slices.Sort(operators)
		cs.LogInfo("active", "streams", operators)
	}
	return
}

func (cs *CertStream) removeStream(ls *LogStream) {
	cs.lifecycleMu.Lock()
	defer cs.lifecycleMu.Unlock()
	lo := ls.LogOperator
	lo.mu.Lock()
	if lo.streams[ls.URL()] == ls {
		delete(lo.streams, ls.URL())
	}
	empty := len(lo.streams) == 0
	lo.mu.Unlock()
	if empty {
		cs.mu.Lock()
		if cs.operators[lo.Domain] == lo {
			delete(cs.operators, lo.Domain)
		}
		cs.mu.Unlock()
	}
}

func (cs *CertStream) retireStreams(ctx context.Context, retired map[string]bool, states map[string]*loglist3.LogStates) (err error) {
	db := cs.DB()
	var ids []int32
	if db != nil {
		urls := make([]string, 0, len(states))
		values := make([]string, 0, len(states))
		for url, state := range states {
			var value []byte
			if value, err = json.Marshal(state); err != nil {
				break
			}
			urls = append(urls, url)
			values = append(values, string(value))
		}
		if err == nil && len(urls) > 0 {
			_, err = db.Exec(ctx, db.Pfx(`UPDATE CERTDB_stream AS s
SET json = jsonb_set(s.json::jsonb, '{state}', v.state::jsonb)::text
FROM unnest($1::text[], $2::text[]) AS v(url, state)
WHERE s.url = v.url
  AND COALESCE((s.json::jsonb->'state') ? 'retired', FALSE) <> (v.state::jsonb ? 'retired')`), urls, values)
		}
		if err == nil {
			rows, e := db.Query(ctx, db.Pfx(`SELECT id, url FROM CERTDB_stream WHERE (json::jsonb->'state') ? 'retired' ORDER BY id`))
			err = e
			if err == nil {
				for rows.Next() {
					var id int32
					var url string
					if err = rows.Scan(&id, &url); err != nil {
						break
					}
					ids = append(ids, id)
					retired[url] = true
				}
				if err == nil {
					err = rows.Err()
				}
				rows.Close()
			}
		}
	}
	var stopped []*LogStream
	for _, op := range cs.Operators() {
		for _, ls := range op.Streams() {
			if retired[ls.URL()] && ls.cancel != nil {
				ls.cancel()
				stopped = append(stopped, ls)
			}
		}
	}
	for _, ls := range stopped {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ls.done:
		}
	}
	if err != nil || db == nil || cs.OnRetiredStreams == nil || len(ids) == 0 {
		return
	}
	if err = db.flushWorkers(ctx); err != nil {
		return
	}
	err = cs.OnRetiredStreams(ctx, db, ids)
	return
}
