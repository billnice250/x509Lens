package viewer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"certview/internal/core"
)

func certificateFile(t *testing.T, name string) string {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name+".cer")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestOneDocumentAndPublicExports(t *testing.T) {
	s := New(t.TempDir())
	defer s.Close()
	first, err := s.Open(t.Context(), certificateFile(t, "first"), "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Open(t.Context(), certificateFile(t, "second"), "")
	if err != nil {
		t.Fatal(err)
	}
	if second.Name != "second.cer" || len(second.Result.Items) != 1 || second.Result.Items[0].ID == first.Result.Items[0].ID {
		t.Fatal("opening a file did not replace the document")
	}
	if second.Online || len(second.Result.Activity) > 0 {
		t.Fatal("opening a file performed network operations")
	}
	id := second.Result.Items[0].ID
	for _, format := range []string{"pem", "der", "p7b"} {
		data, _, err := s.Export(id, format, "object", 0)
		if err != nil {
			t.Fatal(err)
		}
		e := core.New(core.Options{})
		if err = e.Load("roundtrip", data); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if len(e.Items) != 1 || e.Items[0].ID != id {
			t.Fatal("export changed certificate")
		}
	}
	for _, tc := range [][3]string{{"unknown", "pem", "object"}, {id, "invalid", "object"}, {id, "der", "chain"}, {id, "pem", "invalid"}} {
		if _, _, err = s.Export(tc[0], tc[1], tc[2], 0); err == nil {
			t.Fatal("invalid export accepted", tc)
		}
	}
	verified, err := s.Verify(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Online || len(verified.Result.Activity) > 0 {
		t.Fatal("offline verification used network")
	}
}
func TestEncryptedMetadataSurvivesVerification(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("optional OpenSSL unavailable")
	}
	s := New(t.TempDir())
	defer s.Close()
	doc, err := s.Open(t.Context(), "../../examples/test-encrypted.pem", "")
	if err != nil {
		t.Fatal(err)
	}
	if !doc.NeedsPassword {
		t.Fatal("missing password prompt")
	}
	doc, err = s.Open(t.Context(), s.Path(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	if doc.NeedsPassword || len(doc.Result.Items) == 0 {
		t.Fatalf("unlock failed: %+v", doc)
	}
	keyID := ""
	for _, it := range doc.Result.Items {
		if it.Kind == "private-key" {
			keyID = it.ID
		}
	}
	if keyID == "" {
		t.Fatal("missing key metadata")
	}
	if _, _, err = s.Export(keyID, "pem", "object", 0); err == nil {
		t.Fatal("private key export allowed")
	}
	doc, err = s.Verify(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range doc.Result.Items {
		if it.ID == keyID {
			found = true
			if it.PEM != "" {
				t.Fatal("private bytes exposed")
			}
		}
	}
	if !found {
		t.Fatal("verification lost key metadata")
	}
}
func TestOpenLimitsAndCancellation(t *testing.T) {
	s := New("")
	defer s.Close()
	dir := t.TempDir()
	if _, err := s.Open(t.Context(), dir, ""); err == nil {
		t.Fatal("directory accepted")
	}
	path := filepath.Join(dir, "large")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err = s.Open(t.Context(), path, ""); err == nil {
		t.Fatal("oversized file accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = s.Open(ctx, certificateFile(t, "canceled"), ""); err == nil {
		t.Fatal("canceled open succeeded")
	}
	_, first := s.begin(t.Context())
	_, second := s.begin(t.Context())
	if _, err = s.commit(first, "old", Document{Name: "old"}); err != ErrSuperseded {
		t.Fatal("stale result accepted")
	}
	if _, err = s.commit(second, "new", Document{Name: "new"}); err != nil {
		t.Fatal(err)
	}
}
