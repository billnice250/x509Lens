package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func hierarchy(t *testing.T) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &key.PublicKey
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1}}
	raw, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = x509.ParseCertificate(raw)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Leaf"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter}
	raw, err = x509.CreateCertificate(rand.Reader, leaf, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(raw)
	return root, leaf, key
}
func TestTrustAndSources(t *testing.T) {
	root, leaf, _ := hierarchy(t)
	for _, tc := range []struct {
		source          string
		custom, trusted bool
	}{{"bundle", false, false}, {"bundle", true, true}, {"AIA: https://example.com", true, false}} {
		e := New(Options{CustomRoots: tc.custom})
		e.addCert(root, tc.source)
		e.addCert(leaf, "leaf")
		paths := e.buildPaths()
		found := false
		for _, p := range paths {
			if p.Leaf == fingerprint(leaf.Raw) {
				found = true
				if p.Trusted != tc.trusted {
					t.Fatalf("%+v: %+v", tc, p)
				}
				if len(p.Nodes) != 2 {
					t.Fatal(p)
				}
			}
		}
		if !found {
			t.Fatal("missing leaf")
		}
	}
}
func TestNetworkRestrictions(t *testing.T) {
	e := New(Options{})
	for _, raw := range []string{"http://127.0.0.1", "http://169.254.169.254", "http://[::1]", "http://100.64.1.1", "file:///etc/passwd", "https://user:secret@127.0.0.1"} {
		u, _ := url.Parse(raw)
		if e.checkURL(u) == nil {
			t.Fatal(raw)
		}
	}
	if _, err := e.dialContext(t.Context(), "tcp", net.JoinHostPort("127.0.0.1", "80")); err == nil {
		t.Fatal("private dial accepted")
	}
}
func TestCRLScopeAndFreshness(t *testing.T) {
	root, _, key := hierarchy(t)
	for _, tc := range []struct {
		next  time.Time
		ext   []pkix.Extension
		valid bool
	}{{time.Now().Add(time.Hour), nil, true}, {time.Now().Add(-time.Minute), nil, false}, {time.Now().Add(time.Hour), []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Value: []byte{0x30, 0}}}, false}} {
		raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: tc.next, ExtraExtensions: tc.ext}, root, key)
		if err != nil {
			t.Fatal(err)
		}
		crl, err := x509.ParseRevocationList(raw)
		if err != nil {
			t.Fatal(err)
		}
		if (applicableCRL(crl, root) == nil) != tc.valid {
			t.Fatal(tc)
		}
	}
}
func TestOCSPValidation(t *testing.T) {
	root, leaf, key := hierarchy(t)
	for _, tc := range []struct {
		status  int
		expired bool
		want    string
	}{{ocsp.Good, false, "GOOD"}, {ocsp.Revoked, false, "REVOKED"}, {ocsp.Unknown, false, "UNKNOWN"}, {ocsp.Good, true, "STALE"}} {
		next := time.Now().Add(time.Hour)
		if tc.expired {
			next = time.Now().Add(-time.Minute)
		}
		raw, err := ocsp.CreateResponse(root, root, ocsp.Response{Status: tc.status, SerialNumber: leaf.SerialNumber, ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: next}, key)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(httpHandler(raw))
		leaf.OCSPServer = []string{server.URL}
		e := New(Options{AllowPrivateNetwork: true})
		r, _ := e.ocsp(leaf, root)
		server.Close()
		if r.Status != tc.want {
			t.Fatalf("%s: %+v", tc.want, r)
		}
	}
}
func TestPrivateMetadata(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := x509.MarshalPKCS8PrivateKey(key)
	e := New(Options{})
	if err := e.Load("key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e.Analyze())
	if len(e.Items) != 1 || e.Items[0].PEM != "" {
		t.Fatal(string(b))
	}
	if err := e.Load("large", make([]byte, (8<<20)+1)); err == nil {
		t.Fatal("size accepted")
	}
}
func FuzzInspectDER(f *testing.F) {
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 1<<16 {
			InspectDER(b)
		}
	})
}

func httpHandler(b []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(b) })
}

func TestOCSPRejectsTamperingAndUnauthorizedResponder(t *testing.T) {
	root, leaf, key := hierarchy(t)
	other, _, otherKey := hierarchy(t)
	other.Subject.CommonName = "Unrelated responder"
	for _, unauthorized := range []bool{false, true} {
		template := ocsp.Response{Status: ocsp.Good, SerialNumber: leaf.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}
		signer := key
		responder := root
		if unauthorized {
			signer = otherKey
			responder = other
			template.Certificate = other
		}
		raw, err := ocsp.CreateResponse(root, responder, template, signer)
		if err != nil {
			t.Fatal(err)
		}
		if !unauthorized {
			raw[len(raw)-1] ^= 1
		}
		server := httptest.NewServer(httpHandler(raw))
		leaf.OCSPServer = []string{server.URL}
		e := New(Options{AllowPrivateNetwork: true})
		r, _ := e.ocsp(leaf, root)
		server.Close()
		if r.Status == "GOOD" || r.Status == "REVOKED" {
			t.Fatalf("unauthenticated result: %+v", r)
		}
	}
}
func TestOfflinePreventsNetwork(t *testing.T) {
	e := New(Options{Offline: true, AllowPrivateNetwork: true})
	if _, err := e.fetch("CRL", "http://127.0.0.1:1"); err == nil {
		t.Fatal("offline fetch accepted")
	}
	if e.requests != 0 {
		t.Fatal("offline requested network")
	}
}
func TestDuplicatePEM(t *testing.T) {
	root, _, _ := hierarchy(t)
	e := New(Options{})
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	for i := 0; i < 2; i++ {
		if err := e.Load("root.pem", data); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.Items) != 1 {
		t.Fatal("duplicate nodes")
	}
}
