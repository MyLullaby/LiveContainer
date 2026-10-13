"""Source contract checks; these do not replace iOS URL/relaunch testing."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReturnToLibraryTests(unittest.TestCase):
    def test_instance_scoping_and_restart_state(self):
        source = (ROOT / "LiveContainer/LCSharedUtils.m").read_text()
        handler = source.split("+ (BOOL)handleReturnToLibraryURL:", 1)[1].split(
            "+ (BOOL)launchToGuestAppWithURL:", 1
        )[0]
        guards = [
            "[url.scheme isEqualToString:NSUserDefaults.lcAppUrlScheme]",
            '[url.host isEqualToString:@"return-to-library"]',
            "if (NSUserDefaults.isLiveProcess) return YES;",
            "if (!NSUserDefaults.lcGuestAppId) return YES;",
        ]
        restart = handler.index("[self launchToGuestAppWithClassicMode:0]")
        for guard in guards:
            self.assertLess(handler.index(guard), restart)
        for state in (
            'setObject:@"ui" forKey:@"selected"',
            'removeObjectForKey:@"selectedContainer"',
            'removeObjectForKey:@"launchAppUrlScheme"',
            'setBool:NO forKey:@"LCOpenSideStore"',
            "[lcUserDefaults synchronize]",
        ):
            self.assertLess(handler.index(state), restart)
        for scheme in ("livecontainer", "livecontainer2", "livecontainer3"):
            self.assertNotIn(f'@"{scheme}"', handler)
        self.assertNotIn("LCLastForegroundGuest", source)

    def test_guest_and_library_entry_points(self):
        guest = (ROOT / "TweakLoader/UIKit+GuestHooks.m").read_text()
        self.assertIn("handleReturnToLibraryURL:url", guest)
        self.assertIn("handleReturnToLibraryURL:[NSURL URLWithString:urlStr]", guest)
        self.assertLess(
            guest.index("handleReturnToLibraryURL:url"),
            guest.index("// pass through sidestore urls"),
        )
        ui = (ROOT / "LiveContainerSwiftUI/Views/LCTabView.swift").read_text()
        self.assertIn("LCSharedUtils.handleReturnToLibraryURL(url)", ui)
        self.assertIn("sharedModel.selectedTab = .apps\n            return", ui)

    def test_action_only_scene_and_delegate_fallbacks(self):
        guest = (ROOT / "TweakLoader/UIKit+GuestHooks.m").read_text()
        self.assertIn("url = ((UIOpenURLAction *)action).url;", guest)
        self.assertIn("if (!decodedUrlStr && !urlStr)", guest)
        self.assertIn("urlStr = ((UIOpenURLAction *)action).url.absoluteString;", guest)
        self.assertIn("if(!decodedUrlStr && urlStr)", guest)
        self.assertIn("[payload removeObjectForKey:UIApplicationLaunchOptionsURLKey]", guest)
        self.assertIn("[actions removeObject:action]", guest)

    @unittest.skipUnless(sys.platform == "darwin", "Requires macOS Foundation")
    def test_payload_url_types_with_foundation(self):
        guest = (ROOT / "TweakLoader/UIKit+GuestHooks.m").read_text()
        helper = "static NSURL *LCURLFromPayload" + guest.split(
            "static NSURL *LCURLFromPayload", 1
        )[1].split("@implementation UIApplication", 1)[0]
        program = '#import <Foundation/Foundation.h>\n#include <assert.h>\n' + helper + r'''
int main(void) {
    @autoreleasepool {
        for (NSString *scheme in @[@"livecontainer", @"livecontainer2", @"livecontainer3"]) {
            NSString *text = [scheme stringByAppendingString:@"://return-to-library"];
            NSURL *url = [NSURL URLWithString:text];
            assert([LCURLFromPayload(text) isEqual:url]);
            assert(LCURLFromPayload(url) == url);
        }
        assert(LCURLFromPayload(nil) == nil);
        assert(LCURLFromPayload(@42) == nil);
        assert(LCURLFromPayload(@{}) == nil);
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "url_test.m"
            binary = Path(directory) / "url_test"
            source.write_text(program)
            subprocess.run(["xcrun", "clang", "-fobjc-arc", "-framework", "Foundation",
                            str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
