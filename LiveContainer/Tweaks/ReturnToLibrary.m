@import UIKit;
#import "LCSharedUtils.h"
#import "LCDebugLog.h"
#import "UIKitPrivate.h"
#import "utils.h"
#import "Tweaks.h"

@interface UIStatusBarManager (LCReturnToLibrary)
- (void)handleTapAction:(id)action;
- (void)lc_handleStatusBarTapAction:(id)action;
@end

@interface UIApplication (LCReturnToLibrary)
- (void)lc_scrollsToTopInitiatorView:(UIView *)view touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event;
@end

// Local status-bar touches can enter UIApplication without a manager tap action.
static NSUInteger LCStatusBarTapDeliveryDepth;

static BOOL LCConsumeStatusBarTripleTap(id owner, NSString *source) {
    NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
    NSMutableArray<NSNumber *> *taps = objc_getAssociatedObject(owner, @selector(lc_handleStatusBarTapAction:));
    if (!taps) {
        taps = [NSMutableArray new];
        objc_setAssociatedObject(owner, @selector(lc_handleStatusBarTapAction:), taps, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    if (taps.count && now - taps.lastObject.doubleValue > 0.45) {
        [taps removeAllObjects];
    }
    [taps addObject:@(now)];
    if (taps.count == 3) {
        [taps removeAllObjects];
        LCDebugLog(@"ReturnToLibrary", @"status bar triple tap via %@", source);
        [LCSharedUtils returnToLibrary];
        return YES;
    }
    return NO;
}

@implementation UIStatusBarManager (LCReturnToLibrary)
- (void)lc_handleStatusBarTapAction:(id)action {
    if (!LCStatusBarTapDeliveryDepth && LCConsumeStatusBarTripleTap(self, @"manager")) return;
    LCStatusBarTapDeliveryDepth++;
    [self lc_handleStatusBarTapAction:action];
    LCStatusBarTapDeliveryDepth--;
}
@end

@implementation UIApplication (LCReturnToLibrary)
- (void)lc_scrollsToTopInitiatorView:(UIView *)view touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    id owner = view.window.windowScene.statusBarManager ?: (id)self;
    if (!LCStatusBarTapDeliveryDepth && LCConsumeStatusBarTripleTap(owner, @"local touches")) return;
    // Nested manager callbacks belong to this same tap, not another user tap.
    LCStatusBarTapDeliveryDepth++;
    [self lc_scrollsToTopInitiatorView:view touchesEnded:touches withEvent:event];
    LCStatusBarTapDeliveryDepth--;
}
@end

void LCReturnToLibraryHooksInit(void) {
    if (!NSUserDefaults.lcGuestAppId) return;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Plugin imports belong to the main library even while a guest owns its process.
        [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
            if ([NSUserDefaults.lcAppUrlScheme isEqualToString:@"livecontainer"] &&
                [NSUserDefaults.lcSharedDefaults stringForKey:@"LCPluginPendingImportURL"].length) {
                [LCSharedUtils returnToLibrary];
            }
        }];
        BOOL managerTapAvailable = [UIStatusBarManager instancesRespondToSelector:@selector(handleTapAction:)];
        BOOL localTapAvailable = [UIApplication instancesRespondToSelector:@selector(_scrollsToTopInitiatorView:touchesEnded:withEvent:)];
        LCDebugLog(@"ReturnToLibrary", @"hooks manager=%d localTouches=%d", managerTapAvailable, localTapAvailable);
        if (localTapAvailable) {
            swizzle(UIApplication.class, @selector(_scrollsToTopInitiatorView:touchesEnded:withEvent:), @selector(lc_scrollsToTopInitiatorView:touchesEnded:withEvent:));
        }
        if (managerTapAvailable) {
            swizzle(UIStatusBarManager.class, @selector(handleTapAction:), @selector(lc_handleStatusBarTapAction:));
        } else {
            LCDebugLog(@"ReturnToLibrary", @"status bar tap handler unavailable");
        }
    });
}
