package certpg

import (
	"time"
)

type LogEntry struct {
	Seen     time.Time // CT log entry timestamp
	LogIndex int64     // CT log index for the stream
	CertID   int64     // database ID of cert
	StreamID int       // database ID of stream
}

func ScanLogEntry(row Scanner, entry *LogEntry) (err error) {
	return row.Scan(
		&entry.Seen,
		&entry.LogIndex,
		&entry.CertID,
		&entry.StreamID,
	)
}
