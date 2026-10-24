//go:build desktop && darwin

package desktop

/*
#cgo LDFLAGS: -framework UniformTypeIdentifiers
*/
import "C"

// Wails 2.17 uses UTType in its native file dialogs. This file explicitly
// links the framework so direct Go builds work with current Apple SDKs too.
