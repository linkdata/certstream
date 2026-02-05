package certstream

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func getCacheDir(baseDir string, monitoringURL string) (cacheDir string) {
	if baseDir != "" {
		cacheDir = path.Join(baseDir, "tilecache")
		if monitoringURL != "" {
			cacheDir = path.Join(cacheDir, urlToFileString(monitoringURL))
		}
	}
	return
}

func pruneCacheFiles(cacheDir string, maxAge time.Duration, now time.Time) (removed int, err error) {
	cutoff := now.Add(-maxAge)
	var dirs []string
	var walkErr error
	walkErr = filepath.WalkDir(cacheDir, func(path string, d fs.DirEntry, walkErr error) error {
		err = errors.Join(err, walkErr)
		if walkErr == nil {
			if d.IsDir() {
				if path != cacheDir {
					dirs = append(dirs, path)
				}
			} else {
				var info fs.FileInfo
				info, walkErr = d.Info()
				err = errors.Join(err, walkErr)
				if walkErr == nil {
					if info.ModTime().Before(cutoff) {
						walkErr = os.Remove(path)
						err = errors.Join(err, walkErr)
						if walkErr == nil {
							removed++
						}
					}
				}
			}
		}
		return nil
	})

	err = errors.Join(err, walkErr)

	// try removing directories
	for i := len(dirs) - 1; i >= 0; i-- {
		if walkErr = os.Remove(dirs[i]); walkErr != nil {
			if !errors.Is(walkErr, syscall.ENOTEMPTY) && !errors.Is(walkErr, os.ErrNotExist) {
				err = errors.Join(err, walkErr)
			}
		}
	}
	return
}

func (cs *CertStream) runCachePruner(ctx context.Context, wg *sync.WaitGroup, cacheDir string, maxAge time.Duration) {
	ticker := time.NewTicker(min(time.Minute, maxAge))
	defer func() {
		ticker.Stop()
		wg.Done()
	}()
	for {
		if _, err := pruneCacheFiles(cacheDir, maxAge, time.Now()); err != nil {
			_ = cs.LogError(err, "runCachePruner", "dir", cacheDir)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
