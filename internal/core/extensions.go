package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"strings"
)

type extensionSpec struct{ oid, name string }

var certificateExtensions = []extensionSpec{
	{"2.5.29.14", "Subject key identifier"},
	{"2.5.29.15", "Key usage"},
	{"2.5.29.17", "Subject alternative name"},
	{"2.5.29.19", "Basic constraints"},
	{"2.5.29.30", "Name constraints"},
	{"2.5.29.31", "CRL distribution points"},
	{"2.5.29.32", "Certificate policies"},
	{"2.5.29.35", "Authority key identifier"},
	{"2.5.29.37", "Extended key usage"},
	{"1.3.6.1.5.5.7.1.1", "Authority information access"},
	{"1.3.6.1.5.5.7.1.24", "TLS feature"},
	{"1.3.6.1.4.1.11129.2.4.2", "Signed certificate timestamps"},
}
var crlExtensions = []extensionSpec{
	{"2.5.29.35", "Authority key identifier"},
	{"2.5.29.20", "CRL number"},
	{"2.5.29.27", "Delta CRL indicator"},
	{"2.5.29.28", "Issuing distribution point"},
	{"2.5.29.46", "Freshest CRL"},
}

func extensionName(oid string) string {
	for _, specs := range [][]extensionSpec{certificateExtensions, crlExtensions} {
		for _, spec := range specs {
			if spec.oid == oid {
				return spec.name
			}
		}
	}
	switch oid {
	case "2.5.29.18":
		return "Issuer alternative name"
	case "2.5.29.33":
		return "Policy mappings"
	case "2.5.29.36":
		return "Policy constraints"
	case "2.5.29.54":
		return "Inhibit any policy"
	case "1.3.6.1.5.5.7.1.11":
		return "Subject information access"
	}
	return "Unrecognized extension"
}
func extensionMetadata(extensions []pkix.Extension, expected []extensionSpec) ([]map[string]any, []map[string]string) {
	present := map[string]bool{}
	encoded := []map[string]any{}
	missing := []map[string]string{}
	for _, ext := range extensions {
		oid := ext.Id.String()
		present[oid] = true
		encoded = append(encoded, map[string]any{"oid": oid, "name": extensionName(oid), "critical": ext.Critical, "der": strings.ToUpper(hex.EncodeToString(ext.Value))})
	}
	for _, spec := range expected {
		if !present[spec.oid] {
			missing = append(missing, map[string]string{"oid": spec.oid, "name": spec.name})
		}
	}
	return encoded, missing
}
func hasExtension(extensions []pkix.Extension, oid string) bool {
	for _, ext := range extensions {
		if ext.Id.String() == oid {
			return true
		}
	}
	return false
}
func keyUsageNames(usage x509.KeyUsage) []string {
	names := []string{}
	for _, bit := range []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital signature"}, {x509.KeyUsageContentCommitment, "Content commitment (non-repudiation)"},
		{x509.KeyUsageKeyEncipherment, "Key encipherment"}, {x509.KeyUsageDataEncipherment, "Data encipherment"},
		{x509.KeyUsageKeyAgreement, "Key agreement"}, {x509.KeyUsageCertSign, "Certificate signing"}, {x509.KeyUsageCRLSign, "CRL signing"},
		{x509.KeyUsageEncipherOnly, "Encipher only"}, {x509.KeyUsageDecipherOnly, "Decipher only"},
	} {
		if usage&bit.flag != 0 {
			names = append(names, bit.name)
		}
	}
	if len(names) == 0 {
		names = append(names, "No key usages asserted")
	}
	return names
}
func extendedKeyUsageNames(c *x509.Certificate) []string {
	labels := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny: "Any extended key usage", x509.ExtKeyUsageServerAuth: "TLS web server authentication", x509.ExtKeyUsageClientAuth: "TLS web client authentication",
		x509.ExtKeyUsageCodeSigning: "Code signing", x509.ExtKeyUsageEmailProtection: "Email protection", x509.ExtKeyUsageIPSECEndSystem: "IPsec end system", x509.ExtKeyUsageIPSECTunnel: "IPsec tunnel", x509.ExtKeyUsageIPSECUser: "IPsec user",
		x509.ExtKeyUsageTimeStamping: "Time stamping", x509.ExtKeyUsageOCSPSigning: "OCSP signing", x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft server-gated cryptography", x509.ExtKeyUsageNetscapeServerGatedCrypto: "Netscape server-gated cryptography", x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft commercial code signing", x509.ExtKeyUsageMicrosoftKernelCodeSigning: "Microsoft kernel code signing",
	}
	names := []string{}
	for _, usage := range c.ExtKeyUsage {
		label, ok := labels[usage]
		if !ok {
			label = "Unrecognized extended key usage"
		}
		names = append(names, label)
	}
	for _, oid := range c.UnknownExtKeyUsage {
		names = append(names, oid.String())
	}
	if len(names) == 0 {
		names = append(names, "No extended key usages asserted")
	}
	return names
}
func basicConstraintsDescription(c *x509.Certificate) string {
	description := "CA: FALSE"
	if c.IsCA {
		description = "CA: TRUE"
		if c.MaxPathLenZero {
			description += ", path length constraint: 0"
		} else if c.MaxPathLen > 0 {
			description += fmt.Sprintf(", path length constraint: %d", c.MaxPathLen)
		} else {
			description += ", path length constraint: unlimited"
		}
	}
	return description
}
func subjectAlternativeNameDescription(c *x509.Certificate) string {
	names := []string{}
	for _, name := range c.DNSNames {
		names = append(names, "DNS: "+name)
	}
	for _, name := range c.EmailAddresses {
		names = append(names, "Email: "+name)
	}
	for _, ip := range c.IPAddresses {
		names = append(names, "IP: "+ip.String())
	}
	for _, uri := range c.URIs {
		names = append(names, "URI: "+uri.String())
	}
	if len(names) == 0 {
		return "No supported names"
	}
	return strings.Join(names, ", ")
}
func certificateExtensionValues(c *x509.Certificate, extensions []map[string]any) {
	for _, ext := range extensions {
		switch ext["oid"] {
		case "2.5.29.15":
			ext["value"] = strings.Join(keyUsageNames(c.KeyUsage), ", ")
		case "2.5.29.37":
			ext["value"] = strings.Join(extendedKeyUsageNames(c), ", ")
		case "2.5.29.19":
			ext["value"] = basicConstraintsDescription(c)
		case "2.5.29.17":
			ext["value"] = subjectAlternativeNameDescription(c)
		}
	}
}

// Add parsed values only when their source extension is actually encoded. Go's
// zero values for an absent extension must not look like assertions in the file.
func certificateExtensionDetails(c *x509.Certificate, d map[string]any) {
	ext, missing := extensionMetadata(c.Extensions, certificateExtensions)
	certificateExtensionValues(c, ext)
	d["extensions"] = ext
	d["missingExtensions"] = missing
	if hasExtension(c.Extensions, "2.5.29.15") {
		d["keyUsage"] = keyUsageNames(c.KeyUsage)
	}
	if hasExtension(c.Extensions, "2.5.29.37") {
		d["extKeyUsage"] = extendedKeyUsageNames(c)
	}
	if hasExtension(c.Extensions, "2.5.29.19") {
		d["isCA"] = c.IsCA
		d["basicConstraints"] = basicConstraintsDescription(c)
		if !c.IsCA {
			d["pathLengthConstraint"] = "Not applicable"
		} else if c.MaxPathLen > 0 || c.MaxPathLenZero {
			d["maxPathLen"] = c.MaxPathLen
			d["pathLengthConstraint"] = c.MaxPathLen
		} else {
			d["pathLengthConstraint"] = "Unlimited"
		}
	}
	if hasExtension(c.Extensions, "2.5.29.14") && len(c.SubjectKeyId) > 0 {
		d["ski"] = fmt.Sprintf("%X", c.SubjectKeyId)
	}
	if hasExtension(c.Extensions, "2.5.29.35") && len(c.AuthorityKeyId) > 0 {
		d["aki"] = fmt.Sprintf("%X", c.AuthorityKeyId)
	}
	if hasExtension(c.Extensions, "2.5.29.17") {
		if len(c.DNSNames) > 0 {
			d["dnsNames"] = c.DNSNames
		}
		if len(c.EmailAddresses) > 0 {
			d["emails"] = c.EmailAddresses
		}
		if len(c.IPAddresses) > 0 {
			values := []string{}
			for _, ip := range c.IPAddresses {
				values = append(values, ip.String())
			}
			d["ips"] = values
		}
		if len(c.URIs) > 0 {
			values := []string{}
			for _, uri := range c.URIs {
				values = append(values, uri.String())
			}
			d["uris"] = values
		}
	}
	if hasExtension(c.Extensions, "1.3.6.1.5.5.7.1.1") {
		if len(c.OCSPServer) > 0 {
			d["ocspServers"] = c.OCSPServer
		}
		if len(c.IssuingCertificateURL) > 0 {
			d["issuingCertificateURLs"] = c.IssuingCertificateURL
		}
	}
	if hasExtension(c.Extensions, "2.5.29.31") && len(c.CRLDistributionPoints) > 0 {
		d["crlDistributionPoints"] = c.CRLDistributionPoints
	}
}
