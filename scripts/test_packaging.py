"""Exercise Linux per-user install/uninstall in an isolated fake home."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class LinuxPackagingTest(unittest.TestCase):
    def test_install_and_remove_preserve_defaults_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / "archive"
            source.mkdir()
            for name in ("install.py", "io.github.billnice250.X509Lens.desktop", "io.github.billnice250.X509Lens.xml", "io.github.billnice250.X509Lens.metainfo.xml"):
                shutil.copy2(ROOT / "packaging/linux" / name, source / name)
            (source / "x509lens").write_bytes(b"test executable")
            (source / "x509lens.png").write_bytes(b"test icon")
            data = base / 'data with spaces and $symbols'
            (data / "applications").mkdir(parents=True)
            defaults = data / "applications/mimeapps.list"
            defaults.write_text("[Default Applications]\napplication/pkix-cert=existing.desktop\n")
            env = dict(os.environ, XDG_DATA_HOME=str(data), PATH=str(base / "no-programs"))
            subprocess.run([sys.executable, str(source / "install.py")], env=env, check=True, capture_output=True)
            self.assertEqual((data / "x509lens/x509lens").read_bytes(), b"test executable")
            launcher = (data / "applications/io.github.billnice250.X509Lens.desktop").read_text()
            self.assertIn('Exec="', launcher)
            self.assertIn(r'\$symbols', launcher)
            self.assertIn("%f", launcher)
            self.assertIn("existing.desktop", defaults.read_text())
            unrelated = data / "x509lens/unrelated.txt"
            unrelated.write_text("keep me")
            subprocess.run([sys.executable, str(data / "x509lens/install.py"), "--uninstall"], env=env, check=True, capture_output=True)
            self.assertFalse((data / "applications/io.github.billnice250.X509Lens.desktop").exists())
            self.assertFalse((data / "x509lens/x509lens").exists())
            self.assertEqual(unrelated.read_text(), "keep me")
            self.assertIn("existing.desktop", defaults.read_text())

if __name__ == "__main__":
    unittest.main()
