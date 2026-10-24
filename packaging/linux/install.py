#!/usr/bin/env python3
"""Install/uninstall X509 Lens for the current Linux user without sudo."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--uninstall", action="store_true")
args = parser.parse_args()
source = Path(__file__).resolve().parent
base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
app = base / "x509lens"
desktop = base / "applications/io.github.billnice250.X509Lens.desktop"
icon = base / "icons/hicolor/1024x1024/apps/io.github.billnice250.X509Lens.png"
mime = base / "mime/packages/io.github.billnice250.X509Lens.xml"
metainfo = base / "metainfo/io.github.billnice250.X509Lens.metainfo.xml"
if args.uninstall:
    for p in (app / "x509lens", app / "install.py", desktop, icon, mime, metainfo):
        p.unlink(missing_ok=True)
    try:
        app.rmdir()
    except OSError:
        pass
else:
    for p in (app, desktop.parent, icon.parent, mime.parent, metainfo.parent):
        p.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / "x509lens", app / "x509lens")
    (app / "x509lens").chmod(0o755)
    shutil.copy2(source / "install.py", app / "install.py")
    shutil.copy2(source / "x509lens.png", icon)
    shutil.copy2(source / "io.github.billnice250.X509Lens.xml", mime)
    shutil.copy2(source / "io.github.billnice250.X509Lens.metainfo.xml", metainfo)
    # Desktop Entry quoting, not shell quoting: Exec is parsed without a shell.
    path = str(app / "x509lens")
    for char in ('\\', '"', '`', '$'):
        path = path.replace(char, "\\" + char)
    desktop.write_text((source / "io.github.billnice250.X509Lens.desktop").read_text().replace("Exec=x509lens %f", 'Exec="' + path + '" %f'))
for command, folder in (("update-mime-database", base / "mime"), ("update-desktop-database", base / "applications")):
    executable = shutil.which(command)
    if executable:
        subprocess.run([executable, str(folder)], check=True)
print("X509 Lens removed." if args.uninstall else "X509 Lens installed. Choose it in Open With; existing defaults were preserved.")
