// Package viewer implements a single-document certificate review session without
// depending on a desktop toolkit. Filesystem paths originate in OS open events
// and native dialogs, never in imported certificate content.
package viewer

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"certview/internal/core"
)

const MaxFileSize = 8 << 20

var ErrSuperseded = errors.New("a newer file or verification replaced this operation")

type Document struct {
	Name          string      `json:"name"`
	Size          int64       `json:"size"`
	Result        core.Result `json:"result"`
	Error         string      `json:"error,omitempty"`
	NeedsPassword bool        `json:"needsPassword"`
	Online        bool        `json:"online"`
}

type Session struct {
	mu         sync.Mutex
	path       string
	document   Document
	generation uint64
	cancel     context.CancelFunc
	cacheDir   string
}

func New(cacheDir string) *Session    { return &Session{cacheDir: cacheDir} }
func (s *Session) Snapshot() Document { s.mu.Lock(); defer s.mu.Unlock(); return s.document }
func (s *Session) Path() string       { s.mu.Lock(); defer s.mu.Unlock(); return s.path }
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}
func (s *Session) begin(ctx context.Context) (context.Context, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	s.generation++
	ctx, s.cancel = context.WithCancel(ctx)
	return ctx, s.generation
}
func (s *Session) commit(generation uint64, path string, doc Document) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.generation {
		return Document{}, ErrSuperseded
	}
	s.path = path
	s.document = doc
	return doc, nil
}

// Open replaces the document rather than accumulating a workspace. Passwords
// are used for this call only. Verification later uses only public objects.
func (s *Session) Open(ctx context.Context, path, password string) (Document, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return Document{}, err
	}
	ctx, generation := s.begin(ctx)
	f, err := os.Open(path)
	if err != nil {
		return Document{}, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Document{}, err
	}
	if !st.Mode().IsRegular() {
		return Document{}, errors.New("choose a regular certificate, CRL, bundle, or key file")
	}
	if st.Size() > MaxFileSize {
		return Document{}, errors.New("file exceeds 8 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return Document{}, err
	}
	if len(data) > MaxFileSize {
		return Document{}, errors.New("file exceeds 8 MiB")
	}
	e := core.New(core.Options{Host: true, Offline: true}).WithContext(ctx)
	loadErr := e.LoadWithPassword(filepath.Base(path), data, password)
	doc := Document{Name: filepath.Base(path), Size: int64(len(data)), Result: e.Analyze()}
	if loadErr != nil {
		doc.Error = loadErr.Error()
	}
	// A PEM bundle may contain public certificates plus an encrypted key; offer
	// unlocking even when public objects were successfully inspected.
	hasPrivate := false
	for _, item := range doc.Result.Items {
		if item.Kind == "private-key" {
			hasPrivate = true
		}
	}
	doc.NeedsPassword = encrypted(data, path) && (loadErr != nil || (bytes.Contains(data, []byte("ENCRYPTED")) && !hasPrivate))
	if doc.NeedsPassword && password != "" && doc.Error == "" && len(doc.Result.Warnings) > 0 {
		doc.Error = doc.Result.Warnings[len(doc.Result.Warnings)-1]
	}

	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	return s.commit(generation, path, doc)
}

func (s *Session) OpenServer(ctx context.Context, endpoint string) (Document, error) {
	ctx, generation := s.begin(ctx)
	e := core.New(core.Options{Host: true, Offline: true}).WithContext(ctx)
	address, err := e.LoadTLSServer(endpoint)
	if err != nil {
		return Document{}, err
	}
	doc := Document{Name: address, Result: e.Analyze()}
	return s.commit(generation, "", doc)
}

func encrypted(data []byte, path string) bool {
	if bytes.Contains(data, []byte("ENCRYPTED")) {
		return true
	}
	var pfx struct {
		Version int
		Content asn1.RawValue
		MAC     asn1.RawValue `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(data, &pfx); err == nil && len(rest) == 0 && pfx.Version == 3 {
		return true
	}
	var p8 struct {
		Algorithm struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue `asn1:"optional"`
		}
		Data []byte
	}
	if rest, err := asn1.Unmarshal(data, &p8); err == nil && len(rest) == 0 && len(p8.Algorithm.OID) > 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".pfx" || ext == ".p12"
}

// Verify reconstructs an engine from public objects. It never retains a PFX
// password or asks the user to unlock the same identity just to check its chain.
func (s *Session) Verify(ctx context.Context, online bool) (Document, error) {
	s.mu.Lock()
	old := s.document
	path := s.path
	if len(old.Result.Items) == 0 {
		s.mu.Unlock()
		return Document{}, errors.New("open a certificate first")
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.generation++
	ctx, s.cancel = context.WithCancel(ctx)
	generation := s.generation
	s.mu.Unlock()
	e := core.New(core.Options{Host: true, AIA: online, Revocation: true, Offline: !online}).WithContext(ctx).WithCacheDirectory(s.cacheDir)
	var metadata []*core.Item
	for _, item := range old.Result.Items {
		if item.Kind == "private-key" || item.PEM == "" {
			metadata = append(metadata, item)
			continue
		}
		if err := e.Load(item.Source, []byte(item.PEM)); err != nil {
			e.Warnings = append(e.Warnings, err.Error())
		}
	}
	doc := old
	doc.Online = online
	doc.Result = e.Analyze()
	doc.Result.Items = append(doc.Result.Items, metadata...)
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	return s.commit(generation, path, doc)
}

// Export only allows known public objects from this document.
func (s *Session) Export(id, format, scope string, pathIndex int) ([]byte, string, error) {
	doc := s.Snapshot()
	var selected *core.Item
	for _, it := range doc.Result.Items {
		if it.ID == id {
			selected = it
			break
		}
	}
	if selected == nil {
		return nil, "", errors.New("select an object to export")
	}
	if selected.Kind == "private-key" {
		return nil, "", errors.New("private-key export is not available")
	}
	items := []*core.Item{selected}
	if scope != "object" {
		if scope != "chain" && scope != "intermediates" {
			return nil, "", errors.New("unsupported export scope")
		}
		paths := []core.Path{}
		for _, p := range doc.Result.Paths {
			for _, node := range p.Nodes {
				if node == id {
					paths = append(paths, p)
					break
				}
			}
		}
		if pathIndex < 0 || pathIndex >= len(paths) {
			return nil, "", errors.New("select an available certification path")
		}
		items = nil
		for _, node := range paths[pathIndex].Nodes {
			for _, it := range doc.Result.Items {
				if it.ID == node {
					items = append(items, it)
					break
				}
			}
		}
		if scope == "intermediates" && len(items) > 1 {
			last := items[len(items)-1]
			if selfSigned(last) {
				items = items[:len(items)-1]
			}
		}
	}
	switch format {
	case "pem":
		var out bytes.Buffer
		for _, it := range items {
			out.WriteString(it.PEM)
		}
		if out.Len() == 0 {
			return nil, "", errors.New("no public PEM available")
		}
		return out.Bytes(), "pem", nil
	case "der":
		if scope != "object" {
			return nil, "", errors.New("DER export requires a single object")
		}
		block, _ := pem.Decode([]byte(selected.PEM))
		if block == nil {
			return nil, "", errors.New("no public DER available")
		}
		return block.Bytes, "der", nil
	case "fingerprint":
		return []byte(selected.ID + "\n"), "txt", nil
	case "p7b":
		return exportPKCS7(items)
	default:
		return nil, "", errors.New("unsupported export format")
	}
}
