import hashlib
import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location(
    "package_ipas", Path(__file__).resolve().parents[1] / ".github/package_ipas.py"
)
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)


class PackageTests(unittest.TestCase):
    def test_preserves_new_runtime_and_old_sidestore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current, old = root / "current.zip", root / "old.zip"
            info = {"CFBundleVersion": "new", "CFBundleURLTypes": [
                {"CFBundleURLSchemes": ["livecontainer"]}
            ]}
            with zipfile.ZipFile(current, "w") as archive:
                archive.writestr(pack.ROOT + "Info.plist", plistlib.dumps(info))
                archive.writestr(pack.ROOT + "Settings.bundle/Root.plist",
                                 plistlib.dumps({"PreferenceSpecifiers": []}))
                for name in (pack.ROOT + "LiveContainer", pack.SUPPORT + "SideStoreSupport"):
                    entry = zipfile.ZipInfo(name)
                    entry.external_attr = 0o100755 << 16
                    archive.writestr(entry, b"new binary")
            info.update(ALTAppGroups=["group.com.SideStore.SideStore"],
                        INIntentsSupported=["RefreshAllIntent"],
                        NSUserActivityTypes=["RefreshAllIntent"])
            info["CFBundleURLTypes"].append({"CFBundleURLSchemes": ["sidestore"]})
            with zipfile.ZipFile(old, "w") as archive:
                archive.writestr(pack.ROOT + "Info.plist", plistlib.dumps(info))
                for name in (
                    pack.COMPONENTS[0] + "SideStore", pack.COMPONENTS[0] + "LCAppInfo.plist",
                    pack.COMPONENTS[1] + "LiveWidgetExtension", pack.COMPONENTS[1] + "Info.plist",
                    pack.COMPONENTS[2] + "extract.actionsdata", *pack.COMPONENTS[3:],
                    pack.ROOT + "LiveContainer", pack.SUPPORT + "SideStoreSupport",
                ):
                    archive.writestr(name, b"old binary")
            with patch.object(pack, "BASE_SHA256", hashlib.sha256(old.read_bytes()).hexdigest()):
                pack.package(current, old, str(root / "LC"))
            with zipfile.ZipFile(root / "LC.ipa") as standard, zipfile.ZipFile(root / "LC+SideStore.ipa") as combined:
                self.assertFalse(any(n.startswith(pack.SUPPORT) for n in standard.namelist()))
                self.assertEqual(combined.read(pack.SUPPORT + "SideStoreSupport"), b"new binary")
                self.assertEqual(combined.read(pack.COMPONENTS[0] + "SideStore"), b"old binary")
                self.assertEqual(combined.getinfo(pack.ROOT + "LiveContainer").external_attr >> 16, 0o100755)
                self.assertEqual(plistlib.loads(combined.read(pack.ROOT + "Info.plist"))["CFBundleVersion"], "new")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                pack.package(current, old, str(root / "rejected"))
            self.assertFalse((root / "rejected.ipa").exists())


if __name__ == "__main__":
    unittest.main()
