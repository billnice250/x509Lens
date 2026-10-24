package core

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestEncryptedAndPFX(t *testing.T) {
	for _, name := range []string{"../../examples/test.p12", "../../examples/test-encrypted.pem"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		e := New(Options{})
		if err = e.LoadWithPassword(name, b, "secret"); err != nil {
			if _, missing := exec.LookPath("openssl"); missing != nil && strings.Contains(err.Error(), "OpenSSL executable required") {
				t.Skip("optional OpenSSL unavailable")
			}
			t.Fatalf("%s: %v", name, err)
		}
		if len(e.Items) == 0 {
			t.Fatalf("%s: no items", name)
		}
		for _, it := range e.Items {
			if it.Kind == "private-key" && it.PEM != "" {
				t.Fatal("private key exported")
			}
		}
	}
}
