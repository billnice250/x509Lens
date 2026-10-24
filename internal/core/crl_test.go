package core

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestCRLRevokedEntries(t *testing.T) {
	root, _, key := hierarchy(t)
	raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(10), RevocationTime: time.Now().Add(-time.Minute), ReasonCode: 1},
			{SerialNumber: big.NewInt(11), RevocationTime: time.Now().Add(-2 * time.Minute), ReasonCode: 5},
		},
	}, root, key)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		t.Fatal(err)
	}
	e := New(Options{})
	e.addCRL(crl, "test.crl")
	d := e.Items[0].Details.(map[string]any)
	revoked := d["revoked"].([]map[string]string)
	if len(revoked) != 2 {
		t.Fatalf("expected all revoked entries, got %#v", revoked)
	}
	if revoked[0]["serial"] != "A" || revoked[0]["reason"] != "Key compromise" {
		t.Fatalf("unexpected first entry: %#v", revoked[0])
	}
	if revoked[1]["serial"] != "B" || revoked[1]["reason"] != "Cessation of operation" {
		t.Fatalf("unexpected second entry: %#v", revoked[1])
	}
}
