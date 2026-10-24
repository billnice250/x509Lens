package core

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// WithCacheDirectory enables a public-response cache. Callers choose the directory;
// it is never taken from an HTTP request. Cached objects remain untrusted input.
func (e *Engine) WithCacheDirectory(dir string) *Engine { e.cacheDir = dir; return e }
func (e *Engine) cachePath(key string) string {
	return filepath.Join(e.cacheDir, fmt.Sprintf("%x", sha256.Sum256([]byte(key))))
}
func (e *Engine) readCache(key string, maxAge time.Duration) []byte {
	if e.cacheDir == "" {
		return nil
	}
	f, err := os.Open(e.cachePath(key))
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 2<<20 || time.Since(st.ModTime()) > maxAge || st.ModTime().After(time.Now()) {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return nil
	}
	return b
}
func (e *Engine) writeCache(key string, b []byte) {
	if e.cacheDir == "" || len(b) > 2<<20 {
		return
	}
	if os.MkdirAll(e.cacheDir, 0700) != nil {
		return
	}
	f, err := os.CreateTemp(e.cacheDir, "response-*")
	if err != nil {
		return
	}
	name := f.Name()
	defer os.Remove(name)
	_, err = f.Write(b)
	closeErr := f.Close()
	if err == nil && closeErr == nil {
		os.Rename(name, e.cachePath(key))
	}
}
