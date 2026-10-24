package viewer

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"sort"

	"certview/internal/core"
)

func selfSigned(item *core.Item) bool {
	block, _ := pem.Decode([]byte(item.PEM))
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return err == nil && bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil
}
func exportPKCS7(items []*core.Item) ([]byte, string, error) {
	certs := [][]byte{}
	for _, item := range items {
		if item.Kind == "certificate" {
			if block, _ := pem.Decode([]byte(item.PEM)); block != nil {
				certs = append(certs, block.Bytes)
			}
		}
	}
	if len(certs) == 0 {
		return nil, "", errors.New("P7B export requires certificates")
	}
	sort.Slice(certs, func(i, j int) bool { return bytes.Compare(certs[i], certs[j]) < 0 })
	type contentInfo struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"optional"`
	}
	content, err := asn1.Marshal(contentInfo{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}})
	if err != nil {
		return nil, "", err
	}
	sd, err := asn1.Marshal(struct {
		Version      int
		Digests      asn1.RawValue
		Content      asn1.RawValue
		Certificates asn1.RawValue
		Signers      asn1.RawValue
	}{1, asn1.RawValue{Tag: 17, IsCompound: true}, asn1.RawValue{FullBytes: content}, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: bytes.Join(certs, nil)}, asn1.RawValue{Tag: 17, IsCompound: true}})
	if err != nil {
		return nil, "", err
	}
	out, err := asn1.Marshal(contentInfo{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sd}})
	return out, "p7b", err
}
