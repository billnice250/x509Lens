package core

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestPublicCache(t *testing.T) {
	e := New(Options{}).WithCacheDirectory(t.TempDir())
	key := "AIA:https://example.org/issuer"
	e.writeCache(key, []byte("public response"))
	if !bytes.Equal(e.readCache(key, time.Hour), []byte("public response")) {
		t.Fatal("cache miss")
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(e.cachePath(key), old, old); err != nil {
		t.Fatal(err)
	}
	if e.readCache(key, time.Hour) != nil {
		t.Fatal("expired cache accepted")
	}
}
func TestMalformedPFXDoesNotFallback(t *testing.T) {
	e := New(Options{})
	if err := e.LoadWithPassword("content.data", []byte{0x30, 5, 2, 1, 3, 0x30, 0}, "incorrect"); err == nil {
		t.Fatal("malformed PFX accepted")
	}
	if len(e.Warnings) > 0 {
		t.Fatalf("unexpected fallback warning: %v", e.Warnings)
	}
}
func TestPFXIncorrectPassword(t *testing.T) {
	b, err := os.ReadFile("../../examples/test.p12")
	if err != nil {
		t.Fatal(err)
	}
	e := New(Options{})
	if err = e.LoadWithPassword("content.data", b, "incorrect"); err == nil {
		t.Fatal("password accepted")
	}
	if len(e.Items) > 0 {
		t.Fatal("incorrect password produced objects")
	}
}
