package certstream

import (
	"context"
	"sync"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/linkdata/certstream/certificate/v1"
	"k8s.io/klog/v2"
)

type LogOperator struct {
	*loglist3.Operator
	LogStreams []*LogStream
}

// Populates `[]*LogStreams` for this log operator. Log operators can have
// multiple log streams (HTTPS endpoints) where the operator puts certificate logs.
// This function will initialize all the non-retired and non-rejected log streams
// for the given operator.
/*func (lo *LogOperator) InitStreams(statuses []loglist3.LogStatus, mbatchSize, nWorkers, startIndex int) {
	var logStreams []*LogStream
	for _, ll := range lo.Operator.Logs {
		if slices.Contains(statuses, ll.State.LogStatus()) {
			ls, err := InitLogStream(ll.URL, lo.Name, mbatchSize, nWorkers, startIndex)
			if err != nil {
				klog.Errorf("error log-source=%s: %v", ll.URL, err)
				continue
			}
			logStreams = append(logStreams, ls)
		}
	}
	lo.LogStreams = logStreams
}*/

// Streams certificate logs from this log operator. This function is run in
// a goroutine and its execution can be stopped or cancelled via the context parameter.
// This function will close the `toSink` channel when its execution is finished.
func (lo *LogOperator) RunStreams(ctx context.Context, toSink chan *certificate.Batch) {
	// Check to make sure there are streams.
	if len(lo.LogStreams) == 0 {
		klog.Infof("Operator=[%s] [0] streams", lo.Name)
		return
	}
	// Each LogStream for this LogOperator gets its own channel on which
	// it sends batches of certificates and closes if the context is cancelled.
	// These channels are aggregated and sent to the `outgoing` channel.
	streams := make([]chan *certificate.Batch, len(lo.LogStreams))
	// Start each LogStream
	var wg sync.WaitGroup
	for _, ls := range lo.LogStreams {
		wg.Add(1)
		stream := make(chan *certificate.Batch, 25)
		streams = append(streams, stream)
		// Each stream receives the channel on which to send back the
		// certificates it finds as well as a context which is used
		// to control the lifetime of the goroutine.
		go func(logSt *LogStream, crtSt chan *certificate.Batch) {
			defer wg.Done()
			logSt.Run(ctx, crtSt)
		}(ls, stream)
	}
	klog.Infof("Operator=[%s] %d streams", lo.Name, len(streams))
	// Receive from each stream's channel in a goroutine, sending batches
	// to the outbound sink's channel. Borrowed this pattern from:
	// https://stackoverflow.com/questions/19992334/how-to-listen-to-n-channels-dynamic-select-statement
	for _, stream := range streams {
		go func(ch chan *certificate.Batch) {
			for batch := range ch {
				toSink <- batch
			}
		}(stream)
	}
	// Wait forever
	wg.Wait()
}
