package certstream

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/google/certificate-transparency-go/loglist3"
)

func (cs *CertStream) ensureOperatorAndLog(ctx context.Context, op *loglist3.Operator, log *loglist3.Log, wg *sync.WaitGroup) (err error) {
	opDom := OperatorDomain(log.URL)

	cs.mu.Lock()
	logop := cs.operators[opDom]
	cs.mu.Unlock()

	if logop == nil {
		logop = &LogOperator{
			CertStream: cs,
			Operator:   op,
			Domain:     opDom,
			streams:    make(map[string]*LogStream),
		}
		sort.Strings(op.Email)
		if db := cs.DB(); db != nil {
			if err = db.ensureOperator(ctx, logop); err == nil {
				cs.mu.Lock()
				cs.operators[opDom] = logop
				cs.mu.Unlock()
			}
		}
	}

	if err == nil {
		err = logop.ensureStream(ctx, log, wg)
	}

	return
}

func (cs *CertStream) updateStreams(ctx context.Context, wg *sync.WaitGroup) (err error) {
	var logList *loglist3.LogList
	if logList, err = getLogList(ctx, cs.HeadClient, loglist3.AllLogListURL); err == nil {
		for _, op := range logList.Operators {
			for _, log := range op.Logs {
				if log.State.LogStatus() == loglist3.UsableLogStatus {
					if e := cs.ensureOperatorAndLog(ctx, op, log, wg); e != nil {
						err = errors.Join(err, e)
					}
				}
			}
		}
	}

	var operators []string
	for _, lo := range cs.Operators() {
		operators = append(operators, fmt.Sprintf("%s*%d", lo.Domain, len(lo.Streams())))
	}
	slices.Sort(operators)
	cs.LogInfo("active", "streams", operators)
	return
}

func (cs *CertStream) removeStream(ls *LogStream) {
	lo := ls.LogOperator
	lo.mu.Lock()
	delete(lo.streams, ls.URL())
	empty := len(lo.streams) == 0
	lo.mu.Unlock()
	if empty {
		cs.mu.Lock()
		delete(cs.operators, lo.Domain)
		cs.mu.Unlock()
	}
}
