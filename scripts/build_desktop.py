#!/usr/bin/env python3
"""Build the native desktop app and package it on the current host OS."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0"

def run(*args, env=None):
    subprocess.run([str(a) for a in args], cwd=ROOT, env=env, check=True)

def app_store_entitlements(profile):
    decoded = subprocess.run(["security", "cms", "-D", "-i", profile], capture_output=True, check=True).stdout
    entitlements = plistlib.loads(decoded).get("Entitlements", {})
    if not entitlements.get("com.apple.application-identifier"):
        raise SystemExit(f"Provisioning profile has no application identifier: {profile}")
    with (ROOT / "packaging/macos/app-store.entitlements").open("rb") as f:
        entitlements.update(plistlib.load(f))
    return entitlements

def clear_macos_extended_attributes(path):
    """Keep Finder/download metadata out of signed distribution bundles."""
    run("xattr", "-cr", path)
    attributes = subprocess.run(
        ["xattr", "-r", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if "com.apple.quarantine" in attributes:
        raise SystemExit(f"Failed to remove quarantine attributes from {path}")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=["amd64", "arm64"], default="arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64")
    parser.add_argument("--installer", action="store_true", help="Require NSIS installer on Windows")
    parser.add_argument("--store", action="store_true", help="Produce a store-submission package where supported")
    args = parser.parse_args()
    host = {"Darwin": "darwin", "Windows": "windows", "Linux": "linux"}[platform.system()]
    env = os.environ.copy()
    if host == "darwin":
        for key in ("CGO_CFLAGS", "CGO_LDFLAGS"):
            if "-mmacosx-version-min=" not in env.get(key, ""):
                env[key] = (env.get(key, "") + " -mmacosx-version-min=12.0").strip()
    run("go", "run", "scripts/make-icon.go")
    wails = [env["WAILS_BIN"]] if env.get("WAILS_BIN") else ["go", "run", "github.com/wailsapp/wails/v2/cmd/wails@v2.17.0"]
    tags = ["-tags", "desktop,webkit2_41"] if host == "linux" else []
    run(*wails, "build", "-s", "-skipbindings", "-m", "-trimpath", "-platform", f"{host}/{args.arch}", *tags, env=env)
    dist = ROOT / "dist" / "desktop"
    dist.mkdir(parents=True, exist_ok=True)
    stem = f"X509Lens-{VERSION}-{'macos' if host == 'darwin' else host}-{args.arch}"
    if host == "darwin":
        app = ROOT / "build/bin/X509 Lens.app"
        identity = os.environ.get("MAC_APP_IDENTITY", "-")
        sign_args = ["codesign", "--force", "--deep", "--sign", identity]
        if identity != "-":
            sign_args += ["--options", "runtime", "--timestamp"]
        if args.store:
            identity = os.environ.get("MAC_APP_STORE_IDENTITY", "")
            installer_identity = os.environ.get("MAC_INSTALLER_IDENTITY", "")
            profile = os.environ.get("MAC_PROVISIONING_PROFILE", "")
            if not identity or not installer_identity:
                raise SystemExit("--store requires MAC_APP_STORE_IDENTITY and MAC_INSTALLER_IDENTITY")
            if profile:
                provision = Path(profile).expanduser()
                if not provision.is_absolute():
                    provision = ROOT / provision
            else:
                profiles = sorted((ROOT / "build" / "darwin").glob("*.provisionprofile"))
                if len(profiles) != 1:
                    raise SystemExit("--store requires MAC_PROVISIONING_PROFILE or exactly one build/darwin/*.provisionprofile")
                provision = profiles[0]
            if not provision.is_file():
                raise SystemExit(f"Provisioning profile not found: {provision}")
            # copy2 preserves the download quarantine attribute from profiles
            # obtained through a browser, which App Store validation rejects.
            shutil.copyfile(provision, app / "Contents" / "embedded.provisionprofile")
            entitlements = app_store_entitlements(provision)
            with tempfile.TemporaryDirectory(prefix="x509lens-entitlements-") as folder:
                entitlements_path = Path(folder) / "entitlements.plist"
                with entitlements_path.open("wb") as f:
                    plistlib.dump(entitlements, f)
                sign_args = ["codesign", "--force", "--deep", "--sign", identity, "--entitlements", entitlements_path, "--options", "runtime", "--timestamp"]
                clear_macos_extended_attributes(app)
                run(*sign_args, app)
        else:
            clear_macos_extended_attributes(app)
            run(*sign_args, app)
        run("codesign", "--verify", "--deep", "--strict", app)
        run("ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", app, dist / (stem + ".zip"))
        with tempfile.TemporaryDirectory(prefix="x509lens-dmg-") as folder:
            stage = Path(folder)
            shutil.copytree(app, stage / "X509 Lens.app", symlinks=True)
            (stage / "Applications").symlink_to("/Applications")
            run("hdiutil", "create", "-volname", "X509 Lens", "-srcfolder", stage, "-ov", "-format", "UDZO", dist / (stem + ".dmg"))
        if args.store:
            run("productbuild", "--component", app, "/Applications", "--sign", installer_identity, dist / (stem + "-AppStore.pkg"))
    elif host == "windows":
        binary = ROOT / "build/bin/X509Lens.exe"
        with zipfile.ZipFile(dist / (stem + ".zip"), "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(binary, "X509Lens.exe")
            archive.write(ROOT / "README.md", "README.md")
        if args.installer:
            nsis = shutil.which("makensis")
            if not nsis:
                raise SystemExit("NSIS makensis is required for --installer; install NSIS and retry.")
            publisher = env.get("WINDOWS_PUBLISHER_DISPLAY_NAME", "X509 Lens")
            run(
                nsis,
                f"/DBINARY={binary}",
                f"/DOUTPUT={dist / (stem + '-setup.exe')}",
                f"/DAPP_VERSION={VERSION}",
                f"/DPUBLISHER_DISPLAY_NAME={publisher}",
                ROOT / "packaging/windows/installer.nsi",
            )
        if args.store:
            makeappx = shutil.which("makeappx")
            required = {key: env.get(key, "") for key in ("WINDOWS_IDENTITY_NAME", "WINDOWS_PUBLISHER", "WINDOWS_PUBLISHER_DISPLAY_NAME")}
            if not makeappx or not all(required.values()):
                raise SystemExit("--store requires makeappx and WINDOWS_IDENTITY_NAME, WINDOWS_PUBLISHER, WINDOWS_PUBLISHER_DISPLAY_NAME from Partner Center")
            with tempfile.TemporaryDirectory(prefix="x509lens-msix-") as folder:
                layout = Path(folder)
                assets = layout / "Assets"
                assets.mkdir()
                shutil.copy2(binary, layout / "X509Lens.exe")
                shutil.copy2(ROOT / "build/store-logo.png", assets / "StoreLogo.png")
                shutil.copy2(ROOT / "build/store-square44.png", assets / "Square44x44Logo.png")
                shutil.copy2(ROOT / "build/store-square150.png", assets / "Square150x150Logo.png")
                manifest = (ROOT / "packaging/windows/AppxManifest.xml").read_text()
                manifest = manifest.replace("{{IDENTITY_NAME}}", required["WINDOWS_IDENTITY_NAME"]).replace("{{PUBLISHER}}", required["WINDOWS_PUBLISHER"]).replace("{{PUBLISHER_DISPLAY_NAME}}", required["WINDOWS_PUBLISHER_DISPLAY_NAME"]).replace("{{ARCH}}", "x64" if args.arch == "amd64" else "arm64")
                (layout / "AppxManifest.xml").write_text(manifest)
                run(makeappx, "pack", "/d", layout, "/p", dist / (stem + ".msix"), "/o")
    else:
        with tempfile.TemporaryDirectory(prefix="x509lens-linux-") as folder:
            stage = Path(folder) / "X509Lens"
            stage.mkdir()
            shutil.copy2(ROOT / "build/bin/X509Lens", stage / "x509lens")
            (stage / "x509lens").chmod(0o755)
            shutil.copy2(ROOT / "build/appicon.png", stage / "x509lens.png")
            for name in ("io.github.billnice250.X509Lens.desktop", "io.github.billnice250.X509Lens.xml", "io.github.billnice250.X509Lens.metainfo.xml", "install.py"):
                shutil.copy2(ROOT / "packaging/linux" / name, stage / name)
            shutil.copy2(ROOT / "README.md", stage / "README.md")
            shutil.make_archive(str(dist / stem), "gztar", folder, "X509Lens")
    paths = sorted(p for p in dist.glob("X509Lens-*") if p.is_file())
    (dist / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in paths))
    print(f"Desktop artifacts: {dist}")

if __name__ == "__main__":
    main()
