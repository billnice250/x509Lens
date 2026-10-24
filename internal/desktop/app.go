//go:build desktop

// Package desktop provides the native window, OS file events and file dialogs.
// No certificate/password HTTP API or local TCP listener is used by this app.
package desktop

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"certview/internal/viewer"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed frontend/*
var frontend embed.FS

type App struct {
	mu      sync.Mutex
	ctx     context.Context
	ready   bool
	pending string
	session *viewer.Session
}

func Run() {
	dir, _ := os.UserCacheDir()
	if dir != "" {
		dir = filepath.Join(dir, "x509lens", "issuers")
	}
	app := &App{session: viewer.New(dir), pending: firstFile(os.Args[1:], "")}
	assets, err := fs.Sub(frontend, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	appOptions := &options.App{
		Title: "X509 Lens", Width: 780, Height: 740, MinWidth: 600, MinHeight: 560,
		BackgroundColour: &options.RGBA{R: 247, G: 248, B: 250, A: 255},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.startup, OnShutdown: app.shutdown,
		Bind:               []interface{}{app},
		Menu:               app.platformMenu(runtime.GOOS),
		DragAndDrop:        dragAndDropOptions(),
		SingleInstanceLock: &options.SingleInstanceLock{UniqueId: "a2ad7d17-dcf9-4951-bc3f-3d41ea118695", OnSecondInstanceLaunch: app.secondInstance},
		Mac:                &mac.Options{OnFileOpen: app.fileOpen, About: &mac.AboutInfo{Title: "X509 Lens", Message: "Certificate and cryptographic object viewer\nPrivate keys are never exported."}},
		Windows:            &windows.Options{Theme: windows.SystemDefault},
		Linux:              &linux.Options{ProgramName: "x509lens"},
	}
	err = wails.Run(appOptions)
	if err != nil {
		log.Fatal(err)
	}
}

func dragAndDropOptions() *options.DragAndDrop {
	return &options.DragAndDrop{EnableFileDrop: true, DisableWebViewDrop: true}
}

// Wails renders its native Windows menu with the classic light Win32 style,
// which clashes with the app's dark appearance. All commands remain available
// in the toolbar, with Windows keyboard shortcuts handled in app.js.
func (a *App) platformMenu(goos string) *menu.Menu {
	if goos == "windows" {
		return nil
	}
	return a.applicationMenu()
}

func firstFile(args []string, workingDir string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if !filepath.IsAbs(arg) && workingDir != "" {
			arg = filepath.Join(workingDir, arg)
		}
		if path, err := filepath.Abs(arg); err == nil {
			return path
		}
	}
	return ""
}
func (a *App) startup(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
	wruntime.OnFileDrop(ctx, func(_, _ int, paths []string) {
		if len(paths) > 0 {
			a.fileOpen(paths[0])
		}
	})
}
func (a *App) shutdown(context.Context) { a.session.Close() }
func (a *App) fileOpen(path string) {
	a.mu.Lock()
	if !a.ready {
		a.pending = path
		a.mu.Unlock()
		return
	}
	ctx := a.ctx
	a.mu.Unlock()
	go func() {
		wruntime.WindowShow(ctx)
		wruntime.WindowUnminimise(ctx)
		wruntime.EventsEmit(ctx, "viewer:busy", true)
		doc, err := a.session.Open(ctx, path, "")
		a.publish(doc, err)
	}()
}
func (a *App) secondInstance(data options.SecondInstanceData) {
	if path := firstFile(data.Args, data.WorkingDirectory); path != "" {
		a.fileOpen(path)
	} else {
		a.mu.Lock()
		ctx := a.ctx
		a.mu.Unlock()
		if ctx != nil {
			wruntime.WindowShow(ctx)
			wruntime.WindowUnminimise(ctx)
		}
	}
}
func (a *App) publish(doc viewer.Document, err error) {
	if errors.Is(err, viewer.ErrSuperseded) || errors.Is(err, context.Canceled) {
		return
	}
	if err != nil {
		wruntime.EventsEmit(a.ctx, "viewer:error", err.Error())
		return
	}
	wruntime.WindowSetTitle(a.ctx, doc.Name+" — X509 Lens")
	wruntime.EventsEmit(a.ctx, "viewer:document", doc)
}

// Ready is called after frontend event handlers have been registered so Finder
// file-open events received during startup cannot be lost.
func (a *App) Ready() (viewer.Document, error) {
	a.mu.Lock()
	a.ready = true
	path := a.pending
	a.pending = ""
	ctx := a.ctx
	a.mu.Unlock()
	if path != "" {
		doc, err := a.session.Open(ctx, path, "")
		if err == nil {
			wruntime.WindowSetTitle(ctx, doc.Name+" — X509 Lens")
		}
		return doc, err
	}
	return a.session.Snapshot(), nil
}
func (a *App) OpenFile() (viewer.Document, error) {
	dialog := wruntime.OpenDialogOptions{Title: "Open certificate or cryptographic object", ResolvesAliases: true}
	if previous := a.session.Path(); previous != "" {
		dialog.DefaultDirectory = filepath.Dir(previous)
	}
	if runtime.GOOS != "darwin" {
		dialog.Filters = []wruntime.FileFilter{{DisplayName: "Certificates, CSRs, bundles, CRLs and keys", Pattern: "*.cer;*.crt;*.csr;*.req;*.pem;*.der;*.p7b;*.p7c;*.p12;*.pfx;*.crl;*.key;*.pub"}, {DisplayName: "All files", Pattern: "*"}}
	}
	path, err := wruntime.OpenFileDialog(a.ctx, dialog)
	if err != nil {
		return viewer.Document{}, err
	}
	if path == "" {
		return a.session.Snapshot(), nil
	}
	doc, err := a.session.Open(a.ctx, path, "")
	if err == nil {
		wruntime.WindowSetTitle(a.ctx, doc.Name+" — X509 Lens")
	}
	return doc, err
}
func (a *App) OpenServer(endpoint string) (viewer.Document, error) {
	doc, err := a.session.OpenServer(a.ctx, endpoint)
	if err == nil {
		wruntime.WindowSetTitle(a.ctx, doc.Name+" — X509 Lens")
	}
	return doc, err
}
func (a *App) Unlock(password string) (viewer.Document, error) {
	path := a.session.Path()
	if path == "" {
		return viewer.Document{}, errors.New("open an encrypted file first")
	}
	return a.session.Open(a.ctx, path, password)
}
func (a *App) Verify(online bool) (viewer.Document, error) { return a.session.Verify(a.ctx, online) }
func (a *App) Export(id, format, scope string, pathIndex int) (bool, error) {
	data, ext, err := a.session.Export(id, format, scope, pathIndex)
	if err != nil {
		return false, err
	}
	name := strings.TrimSuffix(a.session.Snapshot().Name, filepath.Ext(a.session.Snapshot().Name))
	if scope != "object" {
		name += "-chain"
	}
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{Title: "Export public object", DefaultFilename: name + "." + ext, Filters: []wruntime.FileFilter{{DisplayName: strings.ToUpper(ext) + " file", Pattern: "*." + ext}}})
	if err != nil || path == "" {
		return false, err
	}
	if err = os.WriteFile(path, data, 0644); err != nil {
		return false, err
	}
	return true, nil
}
func (a *App) applicationMenu() *menu.Menu {
	m := menu.NewMenu()
	if runtime.GOOS == "darwin" {
		m.Append(menu.AppMenu())
	}
	file := m.AddSubmenu("File")
	file.AddText("Open…", keys.CmdOrCtrl("o"), func(*menu.CallbackData) { go func() { doc, err := a.OpenFile(); a.publish(doc, err) }() })
	file.AddText("Export…", keys.CmdOrCtrl("s"), func(*menu.CallbackData) { wruntime.EventsEmit(a.ctx, "viewer:export") })
	if runtime.GOOS != "darwin" {
		file.AddSeparator()
		file.AddText("Quit", keys.CmdOrCtrl("q"), func(*menu.CallbackData) { wruntime.Quit(a.ctx) })
	}
	m.Append(menu.EditMenu())
	return m
}
