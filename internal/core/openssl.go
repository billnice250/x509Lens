package core

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// OpenSSL is an optional external cryptographic provider. No private key material
// is returned to the browser; decrypted material is parsed in memory; temporary input remains encrypted.
func opensslRun(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "openssl", args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New("OpenSSL operation failed (incorrect password, malformed input, or unsupported encryption)")
	}
	return out, nil
}
func privateTemp(dir, pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}
func (e *Engine) loadEncrypted(name string, raw []byte, password string, pfx bool) error {

	if strings.ContainsAny(password, "\r\n") {
		return errors.New("OpenSSL password cannot contain a line break")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		return errors.New("OpenSSL executable required for encrypted key / PKCS#12 support")
	}
	dir, err := os.MkdirTemp("", "certview-decrypt-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	in, err := privateTemp(dir, "input-*", raw)
	if err != nil {
		return err
	}
	// Password is supplied on stdin, not command-line arguments or environment.
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer cancel()
	var out []byte
	if pfx {
		name += " (PKCS12)"
		out, err = opensslRun(ctx, []byte(password+"\n"), "pkcs12", "-in", in, "-nodes", "-passin", "stdin")
	} else {
		args := []string{"pkey", "-in", in, "-passin", "stdin", "-outform", "PEM"}
		if block, _ := pem.Decode(raw); block == nil {
			args = append(args, "-inform", "DER")
		}
		out, err = opensslRun(ctx, []byte(password+"\n"), args...)
	}
	if err != nil {
		return fmt.Errorf("%s: failed to decrypt (incorrect password or unsupported encryption): %w", name, err)
	}
	// Parse in memory and retain only public key metadata; never return key bytes.
	before := len(e.Items)
	for len(out) > 0 {
		block, remaining := pem.Decode(out)
		if block == nil {
			break
		}
		out = remaining
		if err = e.parseDER(block.Bytes, name+" (decrypted)"); err != nil {
			e.warn(name + ": " + err.Error())
		}
	}
	if len(e.Items) == before {
		return errors.New("no supported objects found after decryption")
	}
	return nil
}
