package core

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type ASN1Node struct {
	Tag      int        `json:"tag"`
	Class    int        `json:"class"`
	Offset   int        `json:"offset"`
	Length   int        `json:"length"`
	Hex      string     `json:"hex"`
	Value    string     `json:"value,omitempty"`
	Children []ASN1Node `json:"children,omitempty"`
}

// ASN1Text returns a bounded, human-readable representation of a DER object.
func ASN1Text(b []byte) (string, error) {
	nodes, err := InspectDER(b)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	var write func([]ASN1Node, int)
	write = func(items []ASN1Node, depth int) {
		for _, n := range items {
			fmt.Fprintf(&out, "%s%04d: %-12s len=%d", strings.Repeat("  ", depth), n.Offset, asn1Label(n.Class, n.Tag), n.Length)
			if n.Value != "" {
				fmt.Fprintf(&out, " value=%q", n.Value)
			} else if len(n.Children) == 0 && n.Hex != "" {
				fmt.Fprintf(&out, " hex=%s", n.Hex)
			}
			out.WriteByte('\n')
			write(n.Children, depth+1)
		}
	}
	write(nodes, 0)
	return out.String(), nil
}

func asn1Label(class, tag int) string {
	if class != 0 {
		return fmt.Sprintf("CLASS-%d[%d]", class, tag)
	}
	names := map[int]string{1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING", 5: "NULL", 6: "OBJECT", 10: "ENUMERATED", 12: "UTF8STRING", 16: "SEQUENCE", 17: "SET", 19: "PRINTABLESTRING", 20: "T61STRING", 22: "IA5STRING", 23: "UTCTIME", 24: "GENERALIZEDTIME"}
	if name := names[tag]; name != "" {
		return name
	}
	return fmt.Sprintf("UNIVERSAL[%d]", tag)
}

// InspectDER bounds both recursion and total work for hostile ASN.1 inputs.
func InspectDER(b []byte) ([]ASN1Node, error) {
	if len(b) > 8<<20 {
		return nil, errors.New("ASN.1 exceeds 8 MiB")
	}
	remaining := 10000
	var parse func([]byte, int, int) ([]ASN1Node, error)
	parse = func(data []byte, offset, depth int) ([]ASN1Node, error) {
		if depth > 32 {
			return nil, errors.New("ASN.1 depth limit")
		}
		nodes := []ASN1Node{}
		for len(data) > 0 {
			remaining--
			if remaining < 0 {
				return nil, errors.New("ASN.1 node limit")
			}
			var raw asn1.RawValue
			rest, err := asn1.Unmarshal(data, &raw)
			if err != nil {
				return nil, err
			}
			n := ASN1Node{Tag: raw.Tag, Class: raw.Class, Offset: offset, Length: len(raw.Bytes), Hex: hex.EncodeToString(raw.FullBytes[:min(len(raw.FullBytes), 256)])}
			if raw.IsCompound {
				n.Children, err = parse(raw.Bytes, offset+len(raw.FullBytes)-len(raw.Bytes), depth+1)
				if err != nil {
					return nil, err
				}
			} else if raw.Class == 0 {
				switch raw.Tag {
				case 6:
					var oid asn1.ObjectIdentifier
					if _, oidErr := asn1.Unmarshal(raw.FullBytes, &oid); oidErr == nil {
						n.Value = oid.String()
						if label := oidName(n.Value); label != "" {
							n.Value += " (" + label + ")"
						}
					}
				case 12, 19, 20, 22, 23, 24:
					n.Value = string(raw.Bytes)
				}
			}
			nodes = append(nodes, n)
			offset += len(raw.FullBytes)
			data = rest
		}
		return nodes, nil
	}
	return parse(b, 0, 0)
}

func oidName(oid string) string {
	names := map[string]string{
		"1.2.840.113549.1.1.1": "RSA encryption", "1.2.840.113549.1.1.5": "SHA-1 with RSA", "1.2.840.113549.1.1.11": "SHA-256 with RSA", "1.2.840.113549.1.1.12": "SHA-384 with RSA", "1.2.840.113549.1.1.13": "SHA-512 with RSA",
		"1.2.840.10045.2.1": "EC public key", "1.2.840.10045.4.3.2": "ECDSA with SHA-256", "1.2.840.10045.4.3.3": "ECDSA with SHA-384", "1.2.840.10045.4.3.4": "ECDSA with SHA-512", "1.3.101.112": "Ed25519",
		"2.5.4.3": "commonName", "2.5.4.6": "countryName", "2.5.4.7": "localityName", "2.5.4.8": "stateOrProvinceName", "2.5.4.10": "organizationName", "2.5.4.11": "organizationalUnitName",
		"2.5.29.14": "subjectKeyIdentifier", "2.5.29.15": "keyUsage", "2.5.29.17": "subjectAltName", "2.5.29.19": "basicConstraints", "2.5.29.31": "crlDistributionPoints", "2.5.29.32": "certificatePolicies", "2.5.29.35": "authorityKeyIdentifier", "2.5.29.37": "extendedKeyUsage", "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
	}
	return names[oid]
}
