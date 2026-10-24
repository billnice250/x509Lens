package core

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

// loadPFX uses the official Go x/crypto PKCS#12 decoder first. Unsupported
// containers can be inspected with the optional OpenSSL fallback.
func (e *Engine) loadPFX(name string, data []byte, password string) error {

	blocks, err := pkcs12.ToPEM(data, password)
	if err == nil {
		before := len(e.Items)
		for _, block := range blocks {
			start := len(e.Items)
			if strings.Contains(block.Type, "PRIVATE KEY") && strings.Contains(block.Type, "ENCRYPTED") {
				e.warn(name + ": nested encrypted key skipped")
				continue
			}
			if er := e.parseDER(block.Bytes, name+" (Go PKCS#12)"); er != nil {
				e.warn(fmt.Sprintf("%s: %v", name, er))
			}
			for _, it := range e.Items[start:] {
				it.Attributes = block.Headers
			}
		}
		if len(e.Items) > before {
			return nil
		}
		return errors.New("PKCS#12 contained no supported objects")
	}
	// Only unsupported native decoding gets fallback; wrong passwords are not retried.
	// x/crypto/pkcs12 returns a distinct incorrect-password error.
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		return fmt.Errorf("%s: incorrect PKCS#12 password", name)
	}
	var unsupported pkcs12.NotImplementedError
	if !errors.As(err, &unsupported) {
		return fmt.Errorf("%s: malformed PKCS#12 or decryption failure", name)
	}
	e.warn(name + ": Go PKCS#12 parser unsupported: " + err.Error() + "; trying OpenSSL fallback")
	return e.loadEncrypted(name, data, password, true)
}

func (e *Engine) loadPrivateEncrypted(name string, block *pem.Block, password string) error {
	if x509.IsEncryptedPEMBlock(block) {
		der, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return fmt.Errorf("%s: legacy PEM decryption: %w", name, err)
		}
		return e.parseDER(der, name+" (Go legacy PEM)")
	}
	// ENCRYPTED PRIVATE KEY (PKCS#8) is deliberately the only key type
	// for which OpenSSL is required.
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return e.loadEncrypted(name, pem.EncodeToMemory(block), password, false)
	}
	return fmt.Errorf("%s: unsupported encrypted PEM type %s", name, block.Type)
}
