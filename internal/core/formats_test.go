package core

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCertificateFormats(t *testing.T) {
	root, leaf, _ := hierarchy(t)
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
	for _, tc := range []struct {
		name  string
		data  []byte
		count int
	}{{"pem", bundle, 2}, {"der", leaf.Raw, 1}, {"collection", append(append([]byte{}, leaf.Raw...), root.Raw...), 2}} {
		e := New(Options{})
		if err := e.Load(tc.name, tc.data); err != nil {
			t.Fatal(err)
		}
		if len(e.Items) != tc.count {
			t.Fatal(tc.name, len(e.Items))
		}
	}
	for _, bad := range [][]byte{{0x30, 0xff}, []byte("-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----")} {
		if New(Options{}).Load("bad", bad) == nil {
			t.Fatal("malformed accepted")
		}
	}
}
func TestPKCS7(t *testing.T) {
	root, leaf, _ := hierarchy(t)
	dataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	signedOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	type content struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"optional"`
	}
	ci, _ := asn1.Marshal(content{Type: dataOID})
	sd, _ := asn1.Marshal(struct {
		Version      int
		Digests      asn1.RawValue
		Content      asn1.RawValue
		Certificates asn1.RawValue
		Signers      asn1.RawValue
	}{1, asn1.RawValue{Tag: 17, IsCompound: true}, asn1.RawValue{FullBytes: ci}, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: bytes.Join([][]byte{leaf.Raw, root.Raw, leaf.Raw}, nil)}, asn1.RawValue{Tag: 17, IsCompound: true}})
	raw, err := asn1.Marshal(content{Type: signedOID, Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sd}})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{raw, pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: raw})} {
		e := New(Options{})
		if err = e.Load("bundle", data); err != nil {
			t.Fatal(err)
		}
		if len(e.Items) != 2 {
			t.Fatal("deduplication failed")
		}
	}
}
func TestRSAFormats(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	for _, raw := range [][]byte{x509.MarshalPKCS1PrivateKey(key), x509.MarshalPKCS1PublicKey(&key.PublicKey), pub, p8} {
		e := New(Options{})
		if err = e.Load("key", raw); err != nil {
			t.Fatal(err)
		}
		d := e.Items[0].Details.(map[string]any)
		for _, field := range []string{"sha1", "sha256", "spkiSHA1", "spkiSHA256", "spkiPinSHA256", "spkiDER", "asn1", "asn1Text"} {
			if d[field] == nil || d[field] == "" {
				t.Fatalf("key is missing %s", field)
			}
		}
	}
}

func TestCSRMetadata(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	e := New(Options{})
	if err = e.Load("request.csr", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})); err != nil {
		t.Fatal(err)
	}
	if len(e.Items) != 1 || e.Items[0].Kind != "csr" {
		t.Fatalf("unexpected CSR items: %#v", e.Items)
	}
	d := e.Items[0].Details.(map[string]any)
	for _, field := range []string{"signatureSHA1", "signatureSHA256", "spkiSHA1", "spkiSHA256", "asn1Text"} {
		if d[field] == nil || d[field] == "" {
			t.Fatalf("CSR is missing %s", field)
		}
	}
	if valid, _ := d["signatureValid"].(bool); !valid {
		t.Fatal("valid CSR signature reported invalid")
	}
}
func TestASN1Limits(t *testing.T) {
	if _, err := InspectDER([]byte{0x30, 0xff}); err == nil {
		t.Fatal("malformed accepted")
	}
	raw := []byte{5, 0}
	for i := 0; i < 40; i++ {
		raw, _ = asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: raw})
	}
	if _, err := InspectDER(raw); err == nil {
		t.Fatal("depth accepted")
	}
}

func TestASN1TextRecognizesOID(t *testing.T) {
	raw, _ := asn1.Marshal(asn1.ObjectIdentifier{2, 5, 29, 19})
	value, err := ASN1Text(raw)
	if err != nil || !bytes.Contains([]byte(value), []byte("basicConstraints")) {
		t.Fatalf("recognized OID missing from ASN.1 text: %q, %v", value, err)
	}
}

func TestLoadTLSServerPresentedChain(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	e := New(Options{Host: true, Offline: true, AllowPrivateNetwork: true})
	address, err := e.LoadTLSServer(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if address == "" || len(e.Items) != 1 || e.Items[0].SourceType != "SERVER_PRESENTED" {
		t.Fatalf("server chain metadata missing: %q %#v", address, e.Items)
	}
	if e.Items[0].Attributes["Server presentation order"] != "1" {
		t.Fatal("presentation order missing")
	}
}
func FuzzLoad(f *testing.F) {
	f.Add([]byte{0x30, 0})
	f.Add([]byte("-----BEGIN CERTIFICATE-----"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 1<<16 {
			New(Options{}).Load("untrusted", b)
		}
	})
}
