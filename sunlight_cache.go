package certstream

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ErrCacheDirCreate = errors.New("cache directory create failed")
var ErrCacheCleanup = errors.New("cache cleanup failed")

type errCacheDirCreate struct {
	dir string
	err error
}

func (e errCacheDirCreate) Error() string {
	return ErrCacheDirCreate.Error() + ": " + e.dir + ": " + e.err.Error()
}

func (e errCacheDirCreate) Unwrap() error {
	return e.err
}

func (e errCacheDirCreate) Is(target error) bool {
	return target == ErrCacheDirCreate
}

type errCacheCleanup struct {
	path string
	err  error
}

func (e errCacheCleanup) Error() string {
	return ErrCacheCleanup.Error() + ": " + e.path + ": " + e.err.Error()
}

func (e errCacheCleanup) Unwrap() error {
	return e.err
}

func (e errCacheCleanup) Is(target error) bool {
	return target == ErrCacheCleanup
}

func normalizeCacheDir(cacheDir string) string {
	cacheDir = strings.TrimSpace(cacheDir)
	if strings.EqualFold(cacheDir, "none") {
		cacheDir = ""
	}
	return cacheDir
}

func cacheDirForMonitoring(baseDir string, monitoringURL string) (cacheDir string) {
	baseDir = normalizeCacheDir(baseDir)
	if baseDir != "" {
		suffix := strings.Trim(strings.ReplaceAll(strings.TrimPrefix(monitoringURL, "https://"), "/", "_"), "_")
		if suffix != "" {
			cacheDir = path.Join(baseDir, suffix)
		} else {
			cacheDir = baseDir
		}
	}
	return
}

func ensureCacheDir(cacheDir string) (err error) {
	if cacheDir != "" {
		if err = os.MkdirAll(cacheDir, 0o700); err != nil {
			err = errCacheDirCreate{dir: cacheDir, err: err}
		}
	}
	return
}

func pruneCacheFiles(cacheDir string, maxAge time.Duration, now time.Time) (removed int, err error) {
	if cacheDir != "" {
		if maxAge > 0 {
			cutoff := now.Add(-maxAge)
			var dirs []string
			var walkErr error
			walkErr = filepath.WalkDir(cacheDir, func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr == nil {
					if d.IsDir() {
						if path != cacheDir {
							dirs = append(dirs, path)
						}
					} else {
						var info fs.FileInfo
						if info, walkErr = d.Info(); walkErr == nil {
							if info.ModTime().Before(cutoff) {
								if walkErr = os.Remove(path); walkErr == nil {
									removed++
								} else if err == nil {
									err = errCacheCleanup{path: path, err: walkErr}
								}
							}
						} else if err == nil {
							err = errCacheCleanup{path: path, err: walkErr}
						}
					}
				} else if err == nil {
					err = errCacheCleanup{path: path, err: walkErr}
				}
				return nil
			})
			if walkErr != nil {
				if err == nil {
					err = errCacheCleanup{path: cacheDir, err: walkErr}
				}
			}
			for i := len(dirs) - 1; i >= 0; i-- {
				if walkErr = os.Remove(dirs[i]); walkErr != nil {
					if !errors.Is(walkErr, syscall.ENOTEMPTY) && !errors.Is(walkErr, os.ErrNotExist) {
						if err == nil {
							err = errCacheCleanup{path: dirs[i], err: walkErr}
						}
					}
				}
			}
		}
	}
	return
}

func (cs *CertStream) startCachePruner(ctx context.Context, wg *sync.WaitGroup) {
	if cs.Config.CacheDir != "" {
		if cs.Config.CacheMaxAge > 0 {
			wg.Add(1)
			go cs.runCachePruner(ctx, wg, cs.Config.CacheDir, cs.Config.CacheMaxAge)
		}
	}
}

func (cs *CertStream) runCachePruner(ctx context.Context, wg *sync.WaitGroup, cacheDir string, maxAge time.Duration) {
	ticker := time.NewTicker(maxAge)
	defer func() {
		ticker.Stop()
		wg.Done()
	}()
	done := false
	for !done {
		if _, err := pruneCacheFiles(cacheDir, maxAge, time.Now()); err != nil {
			_ = cs.LogError(err, "CertStream:cache-prune", "dir", cacheDir)
		}
		select {
		case <-ctx.Done():
			done = true
		case <-ticker.C:
		}
	}
}
