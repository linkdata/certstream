package certstream

import (
	"context"
	"fmt"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/linkdata/certstream/certificate/v1"
	"golang.org/x/net/proxy"
	"k8s.io/klog/v2"
)

var userAgent = "ct-go-scanlog/1.0"

type BatchIndex struct {
	Start int64
	End   int64
}

type LogStream struct {
	*CertStream
	*loglist3.Operator
	*loglist3.Log
	*client.LogClient
	*scanner.Fetcher
}

func (ls *LogStream) String() string {
	return fmt.Sprintf("%s:%s", ls.Operator.Name, ls.Log.URL)
}

func makeHttpClient(cd proxy.ContextDialer) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:           cd.DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func NewLogStream(ctx context.Context, cs *CertStream, op *loglist3.Operator, log *loglist3.Log) (ls *LogStream, err error) {
	var logClient *client.LogClient
	if logClient, err = client.New(log.URL, makeHttpClient(cs), jsonclient.Options{UserAgent: userAgent}); err == nil {
		opts := &scanner.FetcherOptions{
			BatchSize:     cs.BatchSize,
			ParallelFetch: cs.Workers,
			StartIndex:    0,
			Continuous:    true,
		}
		ls = &LogStream{
			Operator:  op,
			Log:       log,
			LogClient: logClient,
			Fetcher:   scanner.NewFetcher(logClient, opts),
		}
	}
	return
}

func (ls *LogStream) Run(ctx context.Context, batchCh chan<- *certificate.Batch) {
	sth, err := ls.Fetcher.Prepare(ctx)
	if err == nil {
		if err = ls.VerifySTHSignature(*sth); err == nil {
			ls.Fetcher.Run(ctx, func(eb scanner.EntryBatch) {
				certs := make([]certificate.Log, 0, len(eb.Entries))
				for n, entry := range eb.Entries {
					index := eb.Start + int64(n)
					logEntry, err := ct.LogEntryFromLeaf(index, &entry)
					if err == nil {
						if cert := ls.newCertPayloadFromLogEntry(logEntry); cert != nil {
							certs = append(certs, *cert)
						}
					}
				}
				batchCh <- &certificate.Batch{
					OperatorName:  ls.Operator.Name,
					LogSourceName: ls.Log.URL,
					Start:         eb.Start,
					End:           eb.Start + int64(len(eb.Entries)),
					Logs:          certs,
				}
			})
		}
	}
	if err != nil {
		klog.Errorf("%q %q: %v", ls.Operator.Name, ls.Log.URL, err)
	}
}

func (ls *LogStream) newCertPayloadFromLogEntry(entry *ct.LogEntry) *certificate.Log {
	// https://github.com/CaliDog/certstream-python/issues/13
	// p.s. Depending on your use case, I'd recommend against excluding pre-certificates
	// from your search - not all CAs log the final certificate (I believe DigiCert, GoDaddy, and Amazon don't),
	// so you'll miss some final certificates unless a third party finds and submits them.
	if entry.X509Cert != nil {
		// handle cert data
		payload := &certificate.Log{
			EntryType: "X509Cert",
			Body: certificate.X509LogEntry{
				Index:    entry.Index,
				Date:     entry.X509Cert.NotBefore.Format("2006-01-02"),
				IssuedAt: entry.X509Cert.NotBefore,
				Source: certificate.LogSource{
					URL:  ls.LogClient.BaseURI(),
					Name: ls.Operator.Name,
				},
				Cert: *certificate.GetInfo(entry.X509Cert),
			},
		}
		// add issue and root certs
		for _, rawASN1 := range entry.Chain {
			cert, err := x509.ParseCertificate(rawASN1.Data)
			if err != nil {
				klog.Errorf("could not parse certificate from ASN1 data: %v", err)
				continue
			}
			certInfo := certificate.GetInfo(cert)
			payload.Body.Chain = append(payload.Body.Chain, *certInfo)
		}
		// return the payload
		return payload
	} else if entry.Precert != nil {
		// handle pre-cert data
		payload := &certificate.Log{
			EntryType: "PreCert",
			Body: certificate.X509LogEntry{
				Index:    entry.Index,
				Date:     entry.Precert.TBSCertificate.NotBefore.Format("2006-01-02"),
				IssuedAt: entry.Precert.TBSCertificate.NotBefore,
				Source: certificate.LogSource{
					URL:  ls.LogClient.BaseURI(),
					Name: ls.Operator.Name,
				},
				Cert: *certificate.GetInfo(entry.Precert.TBSCertificate),
			},
		}
		// add issue and root certs
		for _, rawASN1 := range entry.Chain {
			cert, err := x509.ParseCertificate(rawASN1.Data)
			if err != nil {
				klog.Errorf("could not parse certificate from ASN1 data: %v", err)
				continue
			}
			certInfo := certificate.GetInfo(cert)
			payload.Body.Chain = append(payload.Body.Chain, *certInfo)
		}
		// return the payload
		return payload
	}
	return nil
}
