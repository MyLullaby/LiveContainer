"""Package current LC with the preserved, already dylibified SideStore payload."""
import hashlib
from copy import copy
import plistlib
from pathlib import Path
import sys
import zipfile

ROOT = "Payload/LiveContainer.app/"
SUPPORT = ROOT + "Frameworks/SideStoreSupport.framework/"
COMPONENTS = (
    ROOT + "Frameworks/SideStoreApp.framework/",
    ROOT + "PlugIns/LiveWidgetExtension.appex/",
    ROOT + "Metadata.appintents/",
    ROOT + "Intents.intentdefinition",
    ROOT + "ViewApp.intentdefinition",
)
BASE_SHA256 = "0e1014344b40fe03996c07b8c55221f708b964f22d5087f40b864e6beea53da3"


def package(current_path, preserved_path, scheme):
    # shortcut: SideStore stays at the historical version until a new verified payload is pinned.
    if hashlib.sha256(Path(preserved_path).read_bytes()).hexdigest() != BASE_SHA256:
        raise ValueError("Preserved SideStore IPA checksum mismatch")
    with zipfile.ZipFile(current_path) as current, zipfile.ZipFile(preserved_path) as old:
        for archive in (current, old):
            if archive.testzip() is not None:
                raise ValueError("Corrupt IPA")
        for name in (ROOT + "LiveContainer", SUPPORT + "SideStoreSupport"):
            if not current.read(name):
                raise ValueError(f"Missing current binary: {name}")
        for name in (
            COMPONENTS[0] + "SideStore", COMPONENTS[0] + "LCAppInfo.plist",
            COMPONENTS[1] + "LiveWidgetExtension", COMPONENTS[1] + "Info.plist",
            COMPONENTS[2] + "extract.actionsdata", *COMPONENTS[3:],
        ):
            if not old.read(name):
                raise ValueError(f"Missing preserved component: {name}")
        info = plistlib.loads(current.read(ROOT + "Info.plist"))
        old_info = plistlib.loads(old.read(ROOT + "Info.plist"))
        for key in ("ALTAppGroups", "INIntentsSupported", "NSUserActivityTypes"):
            info[key] = list(dict.fromkeys(info.get(key, []) + old_info[key]))
        urls = info.setdefault("CFBundleURLTypes", [])
        for item in old_info["CFBundleURLTypes"]:
            if "sidestore" in item.get("CFBundleURLSchemes", []) or "sidestore-com.kdt.livecontainer" in item.get("CFBundleURLSchemes", []):
                urls.append(item)
        settings = plistlib.loads(current.read(ROOT + "Settings.bundle/Root.plist"))
        settings["PreferenceSpecifiers"] = [
            item for item in settings["PreferenceSpecifiers"] if item.get("Key") != "LCOpenSideStore"
        ] + [{"Type": "PSToggleSwitchSpecifier", "Title": "Open SideStore",
              "Key": "LCOpenSideStore", "DefaultValue": False}]
        replacements = {
            ROOT + "Info.plist": plistlib.dumps(info),
            ROOT + "Settings.bundle/Root.plist": plistlib.dumps(settings),
        }
        with zipfile.ZipFile(f"{scheme}.ipa", "w", zipfile.ZIP_DEFLATED) as standard, \
             zipfile.ZipFile(f"{scheme}+SideStore.ipa", "w", zipfile.ZIP_DEFLATED) as combined:
            for entry in current.infolist():
                name = entry.filename
                if name.startswith(COMPONENTS):
                    raise ValueError("Current archive already contains embedded SideStore")
                data = current.read(entry)
                if not name.startswith(SUPPORT):
                    standard.writestr(copy(entry), data)
                combined.writestr(copy(entry), replacements.get(name, data))
            for entry in old.infolist():
                if entry.filename.startswith(COMPONENTS):
                    combined.writestr(copy(entry), old.read(entry))
        for path in (f"{scheme}.ipa", f"{scheme}+SideStore.ipa"):
            with zipfile.ZipFile(path) as output:
                assert output.testzip() is None
                assert output.read(ROOT + "LiveContainer") == current.read(ROOT + "LiveContainer")
        with zipfile.ZipFile(f"{scheme}+SideStore.ipa") as output:
            assert output.read(SUPPORT + "SideStoreSupport") == current.read(SUPPORT + "SideStoreSupport")
            assert output.read(COMPONENTS[0] + "SideStore") == old.read(COMPONENTS[0] + "SideStore")


if __name__ == "__main__":
    package(*sys.argv[1:])
