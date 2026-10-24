package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"testing"
)

func TestCertificateExtensionDetails(t *testing.T) {
	c := &x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{0x03, 0x02, 0x05, 0xa0}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0x00}},
		},
	}
	d := map[string]any{}
	certificateExtensionDetails(c, d)

	usages, ok := d["keyUsage"].([]string)
	if !ok {
		t.Fatalf("key usage is not interpreted: %#v", d["keyUsage"])
	}
	if len(usages) != 2 || usages[0] != "Digital signature" || usages[1] != "Key encipherment" {
		t.Fatalf("unexpected key usages: %#v", usages)
	}
	extended, ok := d["extKeyUsage"].([]string)
	if !ok || len(extended) != 1 || extended[0] != "TLS web server authentication" {
		t.Fatalf("unexpected extended key usages: %#v", d["extKeyUsage"])
	}

	if _, present := d["isCA"]; present {
		t.Fatal("absent basic constraints extension produced a default isCA value")
	}
	if _, present := d["dnsNames"]; present {
		t.Fatal("absent subject alternative name extension produced a default value")
	}
	missing := map[string]bool{}
	for _, ext := range d["missingExtensions"].([]map[string]string) {
		missing[ext["oid"]] = true
	}
	for _, oid := range []string{"2.5.29.17", "2.5.29.19", "2.5.29.14", "2.5.29.35"} {
		if !missing[oid] {
			t.Fatalf("missing extension %s was not reported: %#v", oid, missing)
		}
	}
}

func TestCertificateBasicConstraintsAndExtensionValues(t *testing.T) {
	c := &x509.Certificate{
		IsCA:                  true,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{1, 2, 3, 4}},
		Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{0x03, 0x02, 0x01, 0x06}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0x00}},
		},
	}
	d := map[string]any{}
	certificateExtensionDetails(c, d)
	if d["basicConstraints"] != "CA: TRUE, path length constraint: 0" {
		t.Fatalf("unexpected basic constraints: %#v", d["basicConstraints"])
	}
	if d["pathLengthConstraint"] != 0 {
		t.Fatalf("path length constraint not exposed: %#v", d["pathLengthConstraint"])
	}
	for _, ext := range d["extensions"].([]map[string]any) {
		switch ext["oid"] {
		case "2.5.29.15":
			if ext["value"] != "Certificate signing, CRL signing" {
				t.Fatalf("unexpected key usage value: %#v", ext["value"])
			}
		case "2.5.29.19":
			if ext["value"] != "CA: TRUE, path length constraint: 0" {
				t.Fatalf("unexpected basic constraints value: %#v", ext["value"])
			}
		case "2.5.29.37":
			if ext["value"] != "1.2.3.4" {
				t.Fatalf("unknown extended key usage did not fall back to OID: %#v", ext["value"])
			}
		}
	}
}

func TestUnlimitedBasicConstraintsPathLength(t *testing.T) {
	c := &x509.Certificate{IsCA: true, BasicConstraintsValid: true, MaxPathLen: -1, Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}}}
	d := map[string]any{}
	certificateExtensionDetails(c, d)
	if d["pathLengthConstraint"] != "Unlimited" {
		t.Fatalf("unlimited path length not exposed: %#v", d["pathLengthConstraint"])
	}
	if d["basicConstraints"] != "CA: TRUE, path length constraint: unlimited" {
		t.Fatalf("unexpected description: %#v", d["basicConstraints"])
	}
}

func TestSubjectAlternativeNameDescription(t *testing.T) {
	c := &x509.Certificate{
		DNSNames:       []string{"clienttrust.lab"},
		EmailAddresses: []string{"ops@clienttrust.lab"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10")},
		Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 0x00}},
		},
	}
	d := map[string]any{}
	certificateExtensionDetails(c, d)
	for _, ext := range d["extensions"].([]map[string]any) {
		if ext["oid"] == "2.5.29.17" {
			want := "DNS: clienttrust.lab, Email: ops@clienttrust.lab, IP: 192.0.2.10"
			if ext["value"] != want {
				t.Fatalf("unexpected subject alternative name value: %#v", ext["value"])
			}
			return
		}
	}
	t.Fatal("subject alternative name extension missing from metadata")
}
