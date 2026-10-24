package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Item struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Name       string            `json:"name"`
	Source     string            `json:"source"`
	SourceType string            `json:"sourceType"`
	Provenance []string          `json:"provenance,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Details    any               `json:"details"`
	PEM        string            `json:"pem,omitempty"`
	cert       *x509.Certificate
	crl        *x509.RevocationList
}
type Result struct {
	Items    []*Item    `json:"items"`
	Paths    []Path     `json:"paths"`
	Activity []Activity `json:"activity"`
	Warnings []string   `json:"warnings"`
}
type Path struct {
	Leaf       string            `json:"leaf"`
	Nodes      []string          `json:"nodes"`
	Trusted    bool              `json:"trusted"`
	Error      string            `json:"error,omitempty"`
	Revocation []Revocation      `json:"revocation"`
	Validation map[string]string `json:"validation"`
	Checked    string            `json:"checked"`
}
type Revocation struct {
	Certificate string `json:"certificate"`
	Status      string `json:"status"`
	Method      string `json:"method"`
	Source      string `json:"source,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Checked     string `json:"checked,omitempty"`
}
type Activity struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	Status     string `json:"status"`
	Detail     string `json:"detail,omitempty"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	DurationMS int64  `json:"durationMs,omitempty"`
	Size       int    `json:"size,omitempty"`
	CacheHit   bool   `json:"cacheHit"`
}
type Options struct {
	Offline             bool     `json:"offline"`
	Host                bool     `json:"host"`
	AIA                 bool     `json:"aia"`
	Revocation          bool     `json:"revocation"`
	AllowPrivateNetwork bool     `json:"allowPrivateNetwork"`
	TrustAnchors        []string `json:"trustAnchors"`
	CustomRoots         bool     `json:"customRoots"`
}
type Engine struct {
	mu       sync.Mutex
	Items    []*Item
	Activity []Activity
	Warnings []string
	cacheDir string
	ctx      context.Context
	requests int
	opts     Options
	client   *http.Client
	seen     map[string]bool
	cache    map[string][]byte
	revCache map[string]Revocation
}

func New(opts Options) *Engine {
	e := &Engine{ctx: context.Background(), opts: opts, seen: map[string]bool{}, cache: map[string][]byte{}, revCache: map[string]Revocation{}, Items: []*Item{}, Activity: []Activity{}, Warnings: []string{}}
	e.client = &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: e.dialContext}, Timeout: 7 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("too many redirects")
		}
		return e.checkURL(req.URL)
	}}
	return e
}
func (e *Engine) WithContext(ctx context.Context) *Engine { e.ctx = ctx; return e }
func (e *Engine) log(method, u, status, detail string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Activity = append(e.Activity, Activity{Method: method, URL: u, Status: status, Detail: detail})
}
func (e *Engine) warn(s string) { e.Warnings = append(e.Warnings, s) }
func fingerprint(b []byte) string {
	h := sha256.Sum256(b)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}
func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
func digestMetadata(prefix string, b []byte, d map[string]any) {
	d[prefix+"SHA1"] = fmt.Sprintf("%X", sha1.Sum(b))
	d[prefix+"SHA256"] = fmt.Sprintf("%X", sha256.Sum256(b))
}
func addASN1Metadata(der []byte, d map[string]any) {
	if nodes, err := InspectDER(der); err == nil {
		d["asn1"] = nodes
	}
	if value, err := ASN1Text(der); err == nil {
		d["asn1Text"] = value
	}
}
func addSPKIMetadata(publicKey any, d map[string]any) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	d["spkiAlgorithm"] = fmt.Sprint(d["publicKeyAlgorithm"])
	d["spkiDER"] = strings.ToUpper(hex.EncodeToString(spki))
	sum := sha256.Sum256(spki)
	d["spkiPinSHA256"] = "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
	digestMetadata("spki", spki, d)
	return spki, nil
}
func (e *Engine) addCert(c *x509.Certificate, source string) {
	id := fingerprint(c.Raw)
	for _, i := range e.Items {
		if i.ID == id {
			for _, p := range i.Provenance {
				if p == source {
					return
				}
			}
			i.Provenance = append(i.Provenance, source)
			return
		}
	}
	name := c.Subject.CommonName
	if name == "" {
		name = c.Subject.String()
	}
	if name == "" {
		name = "Certificate " + short(id)
	}
	d := map[string]any{"subject": c.Subject.String(), "issuer": c.Issuer.String(), "serial": strings.ToUpper(c.SerialNumber.Text(16)), "notBefore": c.NotBefore, "notAfter": c.NotAfter, "signatureAlgorithm": c.SignatureAlgorithm.String(), "publicKeyAlgorithm": c.PublicKeyAlgorithm.String(), "sha256": id, "sha1": fmt.Sprintf("%X", sha1.Sum(c.Raw)), "rawDER": strings.ToUpper(hex.EncodeToString(c.Raw))}
	digestMetadata("signature", c.Signature, d)
	_, _ = addSPKIMetadata(c.PublicKey, d)
	certificateExtensionDetails(c, d)
	addASN1Metadata(c.Raw, d)
	e.Items = append(e.Items, &Item{ID: id, Kind: "certificate", Name: name, Source: source, SourceType: sourceType(source), Provenance: []string{source}, Details: d, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})), cert: c})
}
func (e *Engine) addCRL(c *x509.RevocationList, source string) {
	rev := []map[string]string{}
	for _, r := range c.RevokedCertificateEntries {
		rev = append(rev, map[string]string{"serial": strings.ToUpper(r.SerialNumber.Text(16)), "date": r.RevocationTime.Format(time.RFC3339), "reason": revocationReasonName(int(r.ReasonCode)), "reasonCode": strconv.Itoa(int(r.ReasonCode))})
	}
	ext, missing := extensionMetadata(c.Extensions, crlExtensions)
	d := map[string]any{"issuer": c.Issuer.String(), "thisUpdate": c.ThisUpdate, "signatureAlgorithm": c.SignatureAlgorithm.String(), "revoked": rev, "count": len(rev), "rawDER": fmt.Sprintf("%X", c.Raw), "extensions": ext, "missingExtensions": missing, "sha256": fingerprint(c.Raw), "sha1": fmt.Sprintf("%X", sha1.Sum(c.Raw))}
	digestMetadata("signature", c.Signature, d)
	if !c.NextUpdate.IsZero() {
		d["nextUpdate"] = c.NextUpdate
	}
	if c.Number != nil && hasExtension(c.Extensions, "2.5.29.20") {
		d["number"] = c.Number
	}
	if len(c.AuthorityKeyId) > 0 && hasExtension(c.Extensions, "2.5.29.35") {
		d["aki"] = fmt.Sprintf("%X", c.AuthorityKeyId)
	}
	addASN1Metadata(c.Raw, d)
	e.Items = append(e.Items, &Item{ID: fingerprint(c.Raw), Kind: "crl", Name: "CRL: " + c.Issuer.String(), Source: source, SourceType: sourceType(source), Provenance: []string{source}, Details: d, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: c.Raw})), crl: c})
}
func revocationReasonName(code int) string {
	switch code {
	case 0:
		return "Unspecified"
	case 1:
		return "Key compromise"
	case 2:
		return "CA compromise"
	case 3:
		return "Affiliation changed"
	case 4:
		return "Superseded"
	case 5:
		return "Cessation of operation"
	case 6:
		return "Certificate hold"
	case 8:
		return "Remove from CRL"
	case 9:
		return "Privilege withdrawn"
	case 10:
		return "AA compromise"
	default:
		return fmt.Sprintf("Unknown reason (%d)", code)
	}
}
func (e *Engine) addKey(key any, private bool, source string, der []byte) {
	if private {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			key = &k.PublicKey
		case *ecdsa.PrivateKey:
			key = &k.PublicKey
		case ed25519.PrivateKey:
			key = k.Public()
		}
	}
	d := map[string]any{}
	publicDER, err := addSPKIMetadata(key, d)
	if err != nil {
		return
	}
	der = publicDER
	kind := "public-key"
	if private {
		kind = "private-key"
	}
	algorithm := "unknown"
	bits := 0
	curve := ""
	switch k := key.(type) {
	case *rsa.PrivateKey:
		algorithm = "RSA"
		bits = k.N.BitLen()
	case *rsa.PublicKey:
		algorithm = "RSA"
		bits = k.N.BitLen()
	case *ecdsa.PrivateKey:
		algorithm = "ECDSA"
		bits = k.Params().BitSize
		curve = k.Curve.Params().Name
	case *ecdsa.PublicKey:
		algorithm = "ECDSA"
		bits = k.Params().BitSize
		curve = k.Curve.Params().Name
	case ed25519.PrivateKey, ed25519.PublicKey:
		algorithm = "Ed25519"
		bits = 256
	}
	publicPEM := ""
	if !private {
		publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	}
	d["algorithm"], d["spkiAlgorithm"], d["bits"], d["curve"] = algorithm, algorithm, bits, curve
	d["sha256"], d["sha1"], d["privateMaterialHidden"] = fingerprint(der), fmt.Sprintf("%X", sha1.Sum(der)), private
	addASN1Metadata(publicDER, d)
	e.Items = append(e.Items, &Item{ID: fingerprint(der), Kind: kind, Name: algorithm + " " + kind, Source: source, SourceType: sourceType(source), Provenance: []string{source}, PEM: publicPEM, Details: d})
}

func (e *Engine) addCSR(c *x509.CertificateRequest, source string) {
	id := fingerprint(c.Raw)
	d := map[string]any{"subject": c.Subject.String(), "signatureAlgorithm": c.SignatureAlgorithm.String(), "publicKeyAlgorithm": c.PublicKeyAlgorithm.String(), "dnsNames": c.DNSNames, "emails": c.EmailAddresses, "ips": c.IPAddresses, "uris": c.URIs, "sha256": id, "sha1": fmt.Sprintf("%X", sha1.Sum(c.Raw)), "rawDER": strings.ToUpper(hex.EncodeToString(c.Raw)), "signatureValid": c.CheckSignature() == nil}
	digestMetadata("signature", c.Signature, d)
	_, _ = addSPKIMetadata(c.PublicKey, d)
	addASN1Metadata(c.Raw, d)
	e.Items = append(e.Items, &Item{ID: id, Kind: "csr", Name: "CSR: " + c.Subject.String(), Source: source, SourceType: sourceType(source), Provenance: []string{source}, Details: d, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: c.Raw}))})
}
func (e *Engine) parseDER(b []byte, source string) error {
	if len(e.Items) >= 2048 {
		return errors.New("object limit reached")
	}
	if c, err := x509.ParseCertificate(b); err == nil {
		e.addCert(c, source)
		return nil
	}
	if cs, err := x509.ParseCertificates(b); err == nil {
		for _, c := range cs {
			e.addCert(c, source)
		}
		return nil
	}
	if c, err := x509.ParseRevocationList(b); err == nil {
		e.addCRL(c, source)
		return nil
	}
	if c, err := x509.ParseCertificateRequest(b); err == nil {
		e.addCSR(c, source)
		return nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		e.addKey(k, true, source, b)
		return nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		e.addKey(k, true, source, b)
		return nil
	}
	if k, err := x509.ParseECPrivateKey(b); err == nil {
		e.addKey(k, true, source, b)
		return nil
	}
	if k, err := x509.ParsePKIXPublicKey(b); err == nil {
		e.addKey(k, false, source, b)
		return nil
	}
	if k, err := x509.ParsePKCS1PublicKey(b); err == nil {
		e.addKey(k, false, source, b)
		return nil
	}
	if err := e.parseP7B(b, source); err == nil {
		return nil
	}
	return errors.New("unrecognized or malformed DER object")
}

// PKCS#7 SignedData ContentInfo: extract the optional IMPLICIT certificates and CRLs sets.
func (e *Engine) parseP7B(b []byte, source string) error {
	source += " (PKCS7)"
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	rest, err := asn1.Unmarshal(b, &ci)
	if err != nil || len(rest) > 0 || !ci.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return errors.New("not PKCS7 signedData")
	}
	var sd asn1.RawValue
	if _, err = asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return err
	}
	if sd.Tag != 16 {
		return errors.New("bad SignedData")
	}
	raw := sd.Bytes
	found := 0
	for len(raw) > 0 {
		var field asn1.RawValue
		var er error
		raw, er = asn1.Unmarshal(raw, &field)
		if er != nil {
			return er
		}
		if field.Class != 2 || (field.Tag != 0 && field.Tag != 1) {
			continue
		}
		inner := field.Bytes
		for len(inner) > 0 {
			var obj asn1.RawValue
			inner, er = asn1.Unmarshal(inner, &obj)
			if er != nil {
				break
			}
			if field.Tag == 0 {
				if c, er := x509.ParseCertificate(obj.FullBytes); er == nil {
					e.addCert(c, source)
					found++
				}
			} else if c, er := x509.ParseRevocationList(obj.FullBytes); er == nil {
				e.addCRL(c, source)
				found++
			}
		}
	}
	if found == 0 {
		return errors.New("PKCS7 contains no supported certificates or CRLs")
	}
	return nil
}
func (e *Engine) Load(name string, b []byte) error { return e.LoadWithPassword(name, b, "") }

// LoadTLSServer performs a certificate-only TLS handshake and imports the
// exact peer chain in server presentation order. Verification remains separate.
func (e *Engine) LoadTLSServer(endpoint string) (string, error) {
	raw := strings.TrimSpace(endpoint)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", errors.New("enter an HTTPS host, optionally with a port")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(u.Hostname(), port)
	ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	conn, err := e.dialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true}) // inspected below using x509.Verify
	defer tlsConn.Close()
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("TLS handshake: %w", err)
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("server returned no certificates")
	}
	for i, cert := range certs {
		e.addCert(cert, fmt.Sprintf("SERVER: %s (presented %d of %d)", address, i+1, len(certs)))
		for _, item := range e.Items {
			if item.ID == fingerprint(cert.Raw) {
				if item.Attributes == nil {
					item.Attributes = map[string]string{}
				}
				item.Attributes["Server presentation order"] = strconv.Itoa(i + 1)
				item.Attributes["TLS endpoint"] = address
			}
		}
	}
	return address, nil
}
func (e *Engine) LoadWithPassword(name string, b []byte, password string) error {
	if len(b) > 8<<20 {
		return errors.New("file exceeds 8 MiB")
	}
	if len(e.Items) >= 2048 {
		return errors.New("object limit reached")
	}
	if isPFX(b) {
		return e.loadPFX(name, b, password)
	}
	if len(b) > 8<<20 {
		return errors.New("file exceeds 8 MiB")
	}
	before := len(e.Items)
	parsed := false
	remain := b
	for {
		block, r := pem.Decode(remain)
		if block == nil {
			break
		}
		remain = r
		if x509.IsEncryptedPEMBlock(block) || strings.Contains(block.Type, "ENCRYPTED") {
			if err := e.loadPrivateEncrypted(name, block, password); err != nil {
				e.warn(err.Error())
			} else {
				parsed = true
			}
			continue
		}
		if err := e.parseDER(block.Bytes, name+" (PEM bundle)"); err != nil {
			e.warn(name + " (" + block.Type + "): " + err.Error())
		} else {
			parsed = true
		}
	}
	if len(e.Items) == before && !parsed {
		if err := e.parseDER(b, name); err == nil {
			return nil
		}
		var encrypted struct {
			Algorithm struct {
				OID    asn1.ObjectIdentifier
				Params asn1.RawValue `asn1:"optional"`
			}
			Data []byte
		}
		if rest, err := asn1.Unmarshal(b, &encrypted); err == nil && len(rest) == 0 && len(encrypted.Algorithm.OID) > 0 {
			return e.loadEncrypted(name, b, password, false)
		}
		return fmt.Errorf("%s: unrecognized or malformed input; encrypted PEM requires its password", name)
	}
	return nil
}
func (e *Engine) checkURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("only HTTP/HTTPS permitted")
	}
	host := u.Hostname()
	if u.User != nil {
		return errors.New("URL credentials are not permitted")
	}
	if host == "" {
		return errors.New("missing hostname")
	}
	if e.opts.AllowPrivateNetwork {
		return nil
	}
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}
	for _, a := range ips {
		ip := a.IP
		if !publicIP(ip) {
			return fmt.Errorf("blocked non-public address %s", ip)
		}
	}
	return nil
}
func (e *Engine) fetch(method, raw string) ([]byte, error) {
	if e.opts.Offline {
		return nil, errors.New("network disabled")
	}
	if method == "AIA" {
		if cached := e.readCache("AIA:"+raw, 24*time.Hour); len(cached) > 0 {
			e.cache[raw] = cached
		}
	}
	if cached, ok := e.cache[raw]; ok {
		e.Activity = append(e.Activity, Activity{Method: method, URL: raw, Status: "CACHE", Size: len(cached), CacheHit: true})
		return cached, nil
	}
	if e.requests >= 64 {
		return nil, errors.New("network request limit reached")
	}
	e.requests++
	start := time.Now()
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if err = e.checkURL(u); err != nil {
		e.log(method, raw, "BLOCKED", err.Error())
		return nil, err
	}
	ctx, cancel := context.WithTimeout(e.ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.log(method, raw, "ERROR", err.Error())
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		err = fmt.Errorf("HTTP %d", resp.StatusCode)
		e.log(method, raw, "ERROR", err.Error())
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
	if len(b) > 2<<20 {
		err = errors.New("response too large")
	}
	if err != nil {
		e.log(method, raw, "ERROR", err.Error())
		return nil, err
	}
	e.cache[raw] = b
	if method == "AIA" {
		e.writeCache("AIA:"+raw, b)
	}
	e.Activity = append(e.Activity, Activity{Method: method, URL: raw, Status: "ONLINE", HTTPStatus: resp.StatusCode, DurationMS: time.Since(start).Milliseconds(), Size: len(b)})
	return b, nil
}
func (e *Engine) discover() {
	if !e.opts.AIA || e.opts.Offline {
		return
	}
	for round := 0; round < 5; round++ {
		changed := false
		existing := append([]*Item(nil), e.Items...)
		for _, it := range existing {
			c := it.cert
			if c == nil || c.CheckSignatureFrom(c) == nil {
				continue
			}
			found := false
			for _, other := range e.Items {
				if other.cert != nil && issuerMatches(c, other.cert) {
					found = true
					break
				}
			}
			if found {
				continue
			}
			for _, u := range c.IssuingCertificateURL {
				if e.seen[u] {
					continue
				}
				e.seen[u] = true
				b, err := e.fetch("AIA", u)
				if err != nil {
					continue
				}
				n := len(e.Items)
				source := "AIA: " + u
				if len(e.Activity) > 0 && e.Activity[len(e.Activity)-1].CacheHit {
					source = "AIA: [cache] " + u
				}
				if err = e.Load(source, b); err != nil {
					e.log("AIA", u, "PARSE ERROR", err.Error())
				}
				if len(e.Items) > n {
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
}
func (e *Engine) buildPaths() []Path {
	var roots *x509.CertPool
	var err error
	if e.opts.Host {
		roots, err = x509.SystemCertPool()
		if err != nil {
			e.warn("Host roots: " + err.Error())
		}
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if e.opts.CustomRoots || len(e.opts.TrustAnchors) > 0 {
		for _, it := range e.Items {
			if it.cert != nil && it.cert.IsCA && !strings.HasPrefix(it.Source, "AIA:") && !strings.HasPrefix(it.Source, "HOST:") && (it.cert.CheckSignatureFrom(it.cert) == nil || len(e.opts.TrustAnchors) > 0) {
				selected := e.opts.CustomRoots
				for _, id := range e.opts.TrustAnchors {
					if id == it.ID {
						selected = true
					}
				}
				if selected {
					roots.AddCert(it.cert)
				}
			}
		}
	}
	pool := x509.NewCertPool()
	certs := []*Item{}
	for _, it := range e.Items {
		if it.cert != nil {
			pool.AddCert(it.cert)
			certs = append(certs, it)
		}
	}
	paths := []Path{}
	for _, it := range certs {
		if err := e.ctx.Err(); err != nil {
			e.warn("analysis canceled")
			break
		}
		if len(paths) >= 512 {
			e.warn("path result limit reached")
			break
		}
		c := it.cert

		p := Path{Leaf: it.ID, Nodes: []string{it.ID}}
		chains, er := c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if er == nil && len(chains) > 0 {
			for _, chain := range chains {
				path := Path{Leaf: it.ID, Trusted: true, Nodes: []string{}, Revocation: []Revocation{}}
				for _, node := range chain {
					path.Nodes = append(path.Nodes, fingerprint(node.Raw))
					if !containsCert(e.Items, node) {
						e.addCert(node, "HOST: verified chain")
					}
				}
				paths = append(paths, path)
			}
			continue
		}
		if er != nil {
			p.Error = er.Error()
		}
		var walk func(*x509.Certificate, []string, map[string]bool)
		count := 0
		walk = func(cur *x509.Certificate, nodes []string, seen map[string]bool) {
			if count >= 128 {
				return
			}
			found := false
			if len(nodes) < 16 && cur.CheckSignatureFrom(cur) != nil {
				for _, candidate := range certs {
					if !seen[candidate.ID] && issuerMatches(cur, candidate.cert) {
						found = true
						next := append(append([]string{}, nodes...), candidate.ID)
						seen[candidate.ID] = true
						walk(candidate.cert, next, seen)
						delete(seen, candidate.ID)
					}
				}
			}
			if !found {
				count++
				paths = append(paths, Path{Leaf: it.ID, Nodes: nodes, Error: p.Error, Revocation: []Revocation{}})
			}
		}
		walk(c, p.Nodes, map[string]bool{it.ID: true})
	}
	return paths
}
func containsCert(items []*Item, c *x509.Certificate) bool {
	for _, it := range items {
		if it.ID == fingerprint(c.Raw) {
			return true
		}
	}
	return false
}
func (e *Engine) revocation(c, issuer *x509.Certificate) Revocation {
	key := fingerprint(c.Raw)
	if issuer != nil {
		key += fingerprint(issuer.Raw)
	}
	if cached, ok := e.revCache[key]; ok {
		return cached
	}
	result := e.checkRevocation(c, issuer)
	e.revCache[key] = result
	return result
}
func (e *Engine) checkRevocation(c, issuer *x509.Certificate) Revocation {
	r := Revocation{Certificate: fingerprint(c.Raw), Status: "UNAVAILABLE", Method: "none", Checked: time.Now().Format(time.RFC3339)}
	if issuer == nil {
		r.Detail = "Issuer not available"
		return r
	}
	if len(c.OCSPServer) > 0 && !e.opts.Offline {
		if result, ok := e.ocsp(c, issuer); ok && (result.Status == "GOOD" || result.Status == "REVOKED") {
			return result
		}
	}
	for _, it := range e.Items {
		if it.crl != nil && applicableCRL(it.crl, issuer) == nil {
			r.Method = "CRL"
			r.Source = it.Source
			r.Status = "GOOD"
			for _, entry := range it.crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(c.SerialNumber) == 0 {
					r.Status = "REVOKED"
					r.Detail = entry.RevocationTime.Format(time.RFC3339)
				}
			}
			return r
		}
	}
	for _, u := range c.CRLDistributionPoints {
		b, err := e.fetch("CRL", u)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(b)
		if block != nil {
			b = block.Bytes
		}
		crl, err := x509.ParseRevocationList(b)
		if err != nil {
			e.log("CRL", u, "PARSE ERROR", err.Error())
			continue
		}
		e.addCRL(crl, "CRL ONLINE: "+u)
		if err = applicableCRL(crl, issuer); err != nil {
			e.log("CRL", u, "UNVERIFIED", err.Error())
			r.Detail = err.Error()
			continue
		}
		if time.Now().Before(crl.ThisUpdate) || (!crl.NextUpdate.IsZero() && time.Now().After(crl.NextUpdate)) {
			r.Status = "STALE"
			r.Method = "CRL"
			r.Source = u
			continue
		}
		r.Status = "GOOD"
		r.Method = "CRL"
		r.Source = "ONLINE: " + u
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(c.SerialNumber) == 0 {
				r.Status = "REVOKED"
				r.Detail = entry.RevocationTime.Format(time.RFC3339)
			}
		}
		return r
	}

	return r
}
func (e *Engine) Analyze() Result {
	e.discover()
	paths := e.buildPaths()
	if e.opts.Revocation {
		byID := map[string]*x509.Certificate{}
		for _, it := range e.Items {
			if it.cert != nil {
				byID[it.ID] = it.cert
			}
		}
		for i := range paths {
			for j := 0; j < len(paths[i].Nodes)-1; j++ {
				c := byID[paths[i].Nodes[j]]
				issuer := byID[paths[i].Nodes[j+1]]
				if c != nil {
					paths[i].Revocation = append(paths[i].Revocation, e.revocation(c, issuer))
				}
			}
			if len(paths[i].Nodes) == 1 {
				paths[i].Revocation = append(paths[i].Revocation, Revocation{Certificate: paths[i].Leaf, Status: "UNAVAILABLE", Detail: "Issuer missing"})
			}
		}
	}
	for i := range paths {
		p := &paths[i]
		p.Checked = time.Now().UTC().Format(time.RFC3339)
		p.Validation = map[string]string{"hostTrust": "UNTRUSTED", "chainIntegrity": "UNKNOWN", "certificateValidity": "VALID", "keyUsage": "NOT_CHECKED", "revocation": "NOT_CHECKED"}
		if p.Trusted {
			p.Validation["hostTrust"] = "TRUSTED"
		}
		if len(p.Nodes) > 1 {
			p.Validation["chainIntegrity"] = "VALID"
		}
		for _, id := range p.Nodes {
			for _, it := range e.Items {
				if it.ID == id && it.cert != nil {
					now := time.Now()
					if now.Before(it.cert.NotBefore) {
						p.Validation["certificateValidity"] = "NOT_YET_VALID"
					}
					if now.After(it.cert.NotAfter) {
						p.Validation["certificateValidity"] = "EXPIRED"
					}
				}
			}
		}
		if e.opts.Revocation {
			p.Validation["revocation"] = "UNKNOWN"
			good := len(p.Revocation) > 0
			for _, r := range p.Revocation {
				if r.Status == "REVOKED" {
					p.Validation["revocation"] = "REVOKED"
					good = false
					break
				}
				if r.Status != "GOOD" {
					good = false
				}
			}
			if good {
				p.Validation["revocation"] = "GOOD"
			}
		}
	}
	sort.Slice(e.Items, func(i, j int) bool { return e.Items[i].Kind < e.Items[j].Kind })
	return Result{Items: e.Items, Paths: paths, Activity: e.Activity, Warnings: e.Warnings}
}
func ReadFiles(paths []string, opts Options) (Result, error) {
	e := New(opts)
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return Result{}, err
		}
		b, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
		f.Close()
		if err != nil {
			return Result{}, err
		}
		if err = e.Load(filepath.Base(p), b); err != nil {
			e.warn(err.Error())
		}
	}
	return e.Analyze(), nil
}
func Marshal(v any) []byte { b, _ := json.Marshal(v); return b }
func PEMBundle(items []*Item, ids []string) string {
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	var b bytes.Buffer
	for _, it := range items {
		if wanted[it.ID] && it.PEM != "" && it.Kind != "private-key" {
			b.WriteString(it.PEM)
		}
	}
	return b.String()
}

func publicIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !net.ParseIP("100.64.0.0").Equal(ip) && !(&net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}).Contains(ip)
}
func (e *Engine) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err = strconv.Atoi(port); err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !e.opts.AllowPrivateNetwork && !publicIP(ip.IP) {
			return nil, errors.New("blocked non-public destination")
		}
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	for _, ip := range ips {
		conn, er := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if er == nil {
			return conn, nil
		}
		err = er
	}
	if err == nil {
		err = errors.New("no destination addresses")
	}
	return nil, err
}

func issuerMatches(c, issuer *x509.Certificate) bool {
	return issuer != nil && bytes.Equal(c.RawIssuer, issuer.RawSubject) && (len(c.AuthorityKeyId) == 0 || len(issuer.SubjectKeyId) == 0 || bytes.Equal(c.AuthorityKeyId, issuer.SubjectKeyId)) && c.CheckSignatureFrom(issuer) == nil
}
func applicableCRL(crl *x509.RevocationList, issuer *x509.Certificate) error {
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return errors.New("CRL issuer mismatch")
	}
	if len(crl.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return errors.New("CRL authority key mismatch")
	}
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 27}) || ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 28}) || ext.Critical {
			return errors.New("UNSUPPORTED: delta, scoped, indirect or critical CRL extension")
		}
	}
	for _, entry := range crl.RevokedCertificateEntries {
		for _, ext := range entry.Extensions {
			if ext.Critical || ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 29}) {
				return errors.New("UNSUPPORTED: indirect CRL entry")
			}
		}
	}
	now := time.Now()
	if crl.ThisUpdate.IsZero() || crl.ThisUpdate.After(now.Add(5*time.Minute)) || crl.NextUpdate.IsZero() || now.After(crl.NextUpdate) {
		return errors.New("CRL freshness unavailable or expired")
	}
	return crl.CheckSignatureFrom(issuer)
}

func isPFX(b []byte) bool {
	var p struct {
		Version  int
		AuthSafe asn1.RawValue
		MAC      asn1.RawValue `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(b, &p)
	return err == nil && len(rest) == 0 && p.Version == 3 && p.AuthSafe.Tag == 16
}

func sourceType(source string) string {
	switch {
	case strings.HasPrefix(source, "AIA:") && strings.Contains(source, "[cache]"):
		return "AIA_CACHE"
	case strings.HasPrefix(source, "AIA:"):
		return "AIA_ONLINE"
	case strings.HasPrefix(source, "HOST:"):
		return "SYSTEM_STORE"
	case strings.HasPrefix(source, "SERVER:"):
		return "SERVER_PRESENTED"
	case strings.Contains(source, "PKCS#12") || strings.Contains(source, "PKCS12"):
		return "PKCS12"
	case strings.Contains(source, "(PKCS7)"):
		return "PKCS7"
	case strings.Contains(source, "(PEM bundle)"):
		return "PEM_BUNDLE"
	default:
		return "FILE"
	}
}
