//go:build desktop

package desktop

import (
	"path/filepath"
	"testing"
)

func TestAssociationArguments(t *testing.T) {
	base := t.TempDir()
	want := filepath.Join(base, "certificate with spaces.crt")
	if got := firstFile([]string{"--", "certificate with spaces.crt"}, base); got != want {
		t.Fatalf("%q != %q", got, want)
	}
	if got := firstFile([]string{"-psn_0_12345"}, base); got != "" {
		t.Fatal(got)
	}
	if got := firstFile([]string{want, "second.crt"}, base); got != want {
		t.Fatal("single-file launch selected wrong file")
	}
}

func TestWindowsUsesWebToolbarWithoutNativeMenu(t *testing.T) {
	if menu := (&App{}).platformMenu("windows"); menu != nil {
		t.Fatal("Windows native menu must remain disabled")
	}
}

func TestNativeFileDropIsEnabled(t *testing.T) {
	options := dragAndDropOptions()
	if !options.EnableFileDrop || !options.DisableWebViewDrop {
		t.Fatalf("unexpected drag-and-drop options: %+v", options)
	}
}
