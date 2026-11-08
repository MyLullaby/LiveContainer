#import "LCGuestURLRouter.h"
#import "LCDebugLog.h"
#import "LCSharedUtils.h"
#import "UIKitPrivate.h"
#import "utils.h"
#import "Tweaks.h"
#include <math.h>

// shortcut: Keep one callback target for 15 minutes; track requests separately if concurrent login flows are needed.
static NSDictionary *returnTarget;
static NSDate *returnDate;
static BOOL initialURLDelivered;
static char LCGuestContextKey, LCGuestSourceKey;

static BOOL LCValidComponent(NSString *value) {
    return value.length && [value isEqualToString:value.lastPathComponent] && ![@[@".", @".."] containsObject:value];
}

static BOOL LCIsGuestScheme(NSString *scheme) {
    return scheme.length && ![@[@"http", @"https", @"file", @"sidestore"] containsObject:scheme.lowercaseString] &&
        ![[LCSharedUtils lcUnorderedUrlSchemes] containsObject:scheme.lowercaseString];
}

static NSArray *LCSchemes(NSDictionary *info) {
    NSMutableArray *schemes = [NSMutableArray new];
    id types = info[@"CFBundleURLTypes"];
    if (![types isKindOfClass:NSArray.class]) return schemes;
    for (id type in types) {
        if (![type isKindOfClass:NSDictionary.class]) continue;
        id values = type[@"CFBundleURLSchemes"];
        if (![values isKindOfClass:NSArray.class]) continue;
        for (id scheme in values) {
            if ([scheme isKindOfClass:NSString.class] && LCIsGuestScheme(scheme)) [schemes addObject:[scheme lowercaseString]];
        }
    }
    return schemes;
}

static NSArray<NSString *> *LCGuestRoots(void) {
    NSMutableArray *roots = [NSMutableArray new];
    NSString *home = @(getenv("LC_HOME_PATH") ?: "");
    if (home.length) [roots addObject:[home stringByAppendingPathComponent:@"Documents/Applications"]];
    static NSURL *primaryDocuments;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSData *bookmark = [NSUserDefaults.lcSharedDefaults dataForKey:@"LCLaunchExtensionPrivateDocBookmark"];
        if (bookmark) {
            BOOL stale = NO;
            NSURL *url = [NSURL URLByResolvingBookmarkData:bookmark options:(1UL << 10) relativeToURL:nil bookmarkDataIsStale:&stale error:nil];
            if ([url startAccessingSecurityScopedResource]) primaryDocuments = url;
        }
    });
    NSString *primary = [primaryDocuments.path stringByAppendingPathComponent:@"Applications"];
    if (primary && ![roots containsObject:primary]) [roots addObject:primary];
    NSString *shared = [[[LCSharedUtils appGroupPath] path] stringByAppendingPathComponent:@"LiveContainer/Applications"];
    if (shared && ![roots containsObject:shared]) [roots addObject:shared];
    NSMutableOrderedSet *resolved = [NSMutableOrderedSet new];
    for (NSString *root in roots) [resolved addObject:root.stringByResolvingSymlinksInPath];
    return resolved.array;
}

static NSArray<NSString *> *LCSharedGuestRoots(void) {
    NSString *root = [LCSharedUtils.appGroupPath.path stringByAppendingPathComponent:@"LiveContainer/Applications"].stringByResolvingSymlinksInPath;
    return root ? @[root] : @[];
}

static NSDictionary *LCTargetForURL(NSURL *url) {
    NSString *scheme = url.scheme.lowercaseString;
    if (!LCIsGuestScheme(scheme)) return nil;
    if ([LCSchemes(NSBundle.mainBundle.infoDictionary) containsObject:scheme]) {
        LCDebugLog(@"GuestURL", @"resolve scheme=%@ result=self", scheme);
        return nil;
    }
    BOOL returning = returnTarget && -returnDate.timeIntervalSinceNow < 900 && [returnTarget[@"schemes"] containsObject:scheme];
    NSDictionary *firstTarget, *runningTarget;
    for (NSString *root in LCSharedGuestRoots()) {
        for (NSString *name in [[NSFileManager.defaultManager contentsOfDirectoryAtPath:root error:nil] sortedArrayUsingSelector:@selector(compare:)]) {
            NSString *path = [root stringByAppendingPathComponent:name];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
            if (![LCSchemes(info) containsObject:scheme]) continue;
            NSDictionary *settings = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"LCAppInfo.plist"]];
            if (!settings) continue;
            NSString *container = settings[@"LCDataUUID"];
            NSMutableArray *containers = [NSMutableArray new];
            if (container) [containers addObject:container];
            for (NSDictionary *entry in settings[@"LCContainers"]) {
                NSString *folder = entry[@"folderName"];
                if (folder && ![containers containsObject:folder]) [containers addObject:folder];
            }
            for (NSString *folder in containers) {
                NSDictionary *target = @{@"bundle": name, @"container": folder};
                // Replies still return to the specific container that initiated the request.
                if (returning && [returnTarget[@"bundle"] isEqualToString:name] && [returnTarget[@"container"] isEqualToString:folder]) {
                    LCDebugLog(@"GuestURL", @"resolve scheme=%@ result=callback bundle=%@ container=%@", scheme, name, folder);
                    return target;
                }
                if (!runningTarget && [LCSharedUtils getContainerUsingLCSchemeWithFolderName:folder]) runningTarget = target;
            }
            if (!firstTarget) firstTarget = @{@"bundle": name, @"container": containers.firstObject ?: @""};
        }
    }
    NSDictionary *target = runningTarget ?: firstTarget;
    LCDebugLog(@"GuestURL", @"resolve scheme=%@ result=%@ bundle=%@ container=%@", scheme, runningTarget ? @"running" : target ? @"installed" : @"not-installed", target[@"bundle"] ?: @"none", target[@"container"] ?: @"none");
    return target;
}

static void LCRouteError(NSString *message) {
    LCDebugLog(@"GuestURL", @"error=%@", message);
    UIViewController *vc = nil;
    for (UIWindowScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] || scene.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *window in scene.windows) if (window.isKeyWindow) vc = window.rootViewController;
    }
    while (vc.presentedViewController) vc = vc.presentedViewController;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"应用间跳转" message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [vc presentViewController:alert animated:YES completion:nil];
}

@implementation LCGuestURLRouter
+ (BOOL)canRouteURL:(NSURL *)url { return !NSUserDefaults.isSideStore && LCTargetForURL(url) != nil; }

+ (NSDictionary *)requestForURL:(NSURL *)url {
    if (![url.scheme.lowercaseString isEqualToString:NSUserDefaults.lcAppUrlScheme.lowercaseString] ||
        ![url.host isEqualToString:@"guest-route"]) return nil;
    NSMutableDictionary *values = [NSMutableDictionary new];
    for (NSURLQueryItem *item in [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO].queryItems) {
        if (!item.value || values[item.name]) return nil;
        values[item.name] = item.value;
    }
    NSString *bundle = values[@"bundle-name"], *container = values[@"container-folder-name"];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:values[@"open-url"] ?: @"" options:0];
    NSString *original = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
    // A never-launched app gets its first data container from runApp.
    if (!LCValidComponent(bundle) || (container && !LCValidComponent(container)) ||
        !original.length || !LCIsGuestScheme([NSURL URLWithString:original].scheme)) return nil;
    values[@"url"] = original;
    return values;
}
@end

static void LCSendGuestURL(NSURL *url, NSDictionary *target, void (^completion)(BOOL)) {
    NSString *container = target[@"container"];
    NSString *running = container.length ? [LCSharedUtils getContainerUsingLCSchemeWithFolderName:container] : nil;
    NSString *destination = running.stringByDeletingPathExtension;
    if (!destination) {
        for (NSString *scheme in @[@"livecontainer2", @"livecontainer3", @"livecontainer"]) {
            if ([scheme isEqualToString:NSUserDefaults.lcAppUrlScheme] ||
                [LCSharedUtils isLCSchemeInUse:scheme] || [LCSharedUtils isLCSchemeInUse:[scheme stringByAppendingString:@".liveprocess"]]) continue;
            if ([NSUserDefaults.lcSharedDefaults stringForKey:@"LCLaunchExtensionBundleID"] &&
                [[NSUserDefaults.lcSharedDefaults stringForKey:@"LCLaunchExtensionScheme"] isEqualToString:scheme] &&
                fabs([[NSUserDefaults.lcSharedDefaults objectForKey:@"LCLaunchExtensionLaunchDate"] timeIntervalSinceNow]) < 3) continue;
            if ([UIApplication.sharedApplication canOpenURL:[NSURL URLWithString:[scheme stringByAppendingString:@"://"]]]) { destination = scheme; break; }
        }
    }
    if (!destination) {
        LCRouteError(@"没有可用的 LiveContainer，请安装 LC2/LC3 或退出其中正在运行的应用后重试。");
        LCDebugLog(@"GuestURL", @"send scheme=%@ bundle=%@ result=no-available-host", url.scheme.lowercaseString, target[@"bundle"]);
        if (completion) completion(NO);
        return;
    }
    NSURLComponents *control = [NSURLComponents new];
    control.scheme = destination;
    control.host = @"guest-route";
    NSMutableArray *query = [NSMutableArray arrayWithArray:@[
        [NSURLQueryItem queryItemWithName:@"bundle-name" value:target[@"bundle"]],
        [NSURLQueryItem queryItemWithName:@"open-url" value:[[url.absoluteString dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0]],
        [NSURLQueryItem queryItemWithName:@"source-bundle" value:NSBundle.mainBundle.bundlePath.lastPathComponent],
        [NSURLQueryItem queryItemWithName:@"source-container" value:@(getenv("HOME")).lastPathComponent]]];
    if (container.length) [query addObject:[NSURLQueryItem queryItemWithName:@"container-folder-name" value:container]];
    control.queryItems = query;
    LCDebugLog(@"GuestURL", @"send scheme=%@ bundle=%@ destination=%@", url.scheme.lowercaseString, target[@"bundle"], destination);
    [UIApplication.sharedApplication openURL:control.URL options:@{} completionHandler:completion];
}

static BOOL LCRouteGuestURL(NSURL *url, void (^completion)(BOOL)) {
    LCDebugLog(@"GuestURL", @"openURL scheme=%@", url.scheme.lowercaseString ?: @"(none)");
    NSDictionary *target = LCTargetForURL(url);
    if (!target) return NO;
    dispatch_async(dispatch_get_main_queue(), ^{ LCSendGuestURL(url, target, completion); });
    return YES;
}

static NSURL *LCDecodeGuestURL(NSURL *url, NSString **source) {
    NSDictionary *request = [LCGuestURLRouter requestForURL:url];
    if (!request) return nil;
    NSURL *original = [NSURL URLWithString:request[@"url"]];
    if (![request[@"bundle-name"] isEqualToString:NSBundle.mainBundle.bundlePath.lastPathComponent] ||
        (request[@"container-folder-name"] && ![request[@"container-folder-name"] isEqualToString:@(getenv("HOME")).lastPathComponent]) ||
        ![LCSchemes(NSBundle.mainBundle.infoDictionary) containsObject:original.scheme.lowercaseString]) return nil;
    NSString *fromContainer = request[@"source-container"];
    NSString *fromBundle = request[@"source-bundle"];
    NSBundle *sourceBundle;
    NSDictionary *settings;
    if (LCValidComponent(fromBundle) && LCValidComponent(fromContainer)) for (NSString *root in LCGuestRoots()) {
        NSString *path = [root stringByAppendingPathComponent:fromBundle];
        NSDictionary *candidate = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"LCAppInfo.plist"]];
        BOOL known = [candidate[@"LCDataUUID"] isEqualToString:fromContainer];
        for (NSDictionary *entry in candidate[@"LCContainers"]) if ([entry[@"folderName"] isEqualToString:fromContainer]) known = YES;
        if (known) { sourceBundle = [NSBundle bundleWithPath:path]; settings = candidate; break; }
    }
    if (sourceBundle) {
        returnTarget = @{@"bundle": fromBundle, @"container": fromContainer,
                         @"schemes": LCSchemes(sourceBundle.infoDictionary),
                         @"identifier": settings[@"LCOrignalBundleIdentifier"] ?: sourceBundle.bundleIdentifier ?: @""};
        returnDate = NSDate.date;
        *source = returnTarget[@"identifier"];
        LCDebugLog(@"GuestURL", @"receive scheme=%@ source=%@ target=%@", original.scheme.lowercaseString, *source, NSUserDefaults.lcGuestAppId);
    } else {
        LCDebugLog(@"GuestURL", @"receive scheme=%@ rejected=unknown-source", original.scheme.lowercaseString);
        return nil;
    }
    return original;
}

@interface UIOpenURLContext (LCGuestURLRouter)
- (NSURL *)lc_guest_URL;
- (UISceneOpenURLOptions *)lc_guest_options;
@end

static NSDictionary *LCGuestContextRequest(UIOpenURLContext *context) {
    @synchronized (context) {
        NSDictionary *cached = objc_getAssociatedObject(context, &LCGuestContextKey);
        if (cached) return cached;
        NSURL *url = [context lc_guest_URL];
        if (![LCGuestURLRouter requestForURL:url]) return nil;
        NSString *source;
        NSURL *decoded = LCDecodeGuestURL(url, &source);
        cached = decoded ? @{@"url": decoded, @"source": source} : @{};
        objc_setAssociatedObject(context, &LCGuestContextKey, cached, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        return cached;
    }
}

@implementation UIOpenURLContext (LCGuestURLRouter)
- (NSURL *)lc_guest_URL {
    NSDictionary *request = LCGuestContextRequest(self);
    return request ? request[@"url"] : [self lc_guest_URL];
}
- (UISceneOpenURLOptions *)lc_guest_options {
    UISceneOpenURLOptions *options = [self lc_guest_options];
    NSDictionary *request = LCGuestContextRequest(self);
    if (request[@"source"]) objc_setAssociatedObject(options, &LCGuestSourceKey, request[@"source"], OBJC_ASSOCIATION_COPY_NONATOMIC);
    return options;
}
@end

@implementation UISceneOpenURLOptions (LCGuestURLRouter)
- (NSString *)lc_guest_sourceApplication {
    return objc_getAssociatedObject(self, &LCGuestSourceKey) ?: [self lc_guest_sourceApplication];
}
@end

@implementation UIApplication (LCGuestURLRouter)
- (BOOL)lc_guest_canOpenURL:(NSURL *)url {
    BOOL routed = [LCGuestURLRouter canRouteURL:url];
    BOOL result = routed || [self lc_guest_canOpenURL:url];
    if (LCIsGuestScheme(url.scheme)) LCDebugLog(@"GuestURL", @"canOpenURL scheme=%@ guest=%d result=%d", url.scheme.lowercaseString, routed, result);
    return result;
}
- (void)lc_guest_openURL:(NSURL *)url options:(NSDictionary *)options completionHandler:(void (^)(BOOL))completion {
    if (!LCRouteGuestURL(url, completion)) [self lc_guest_openURL:url options:options completionHandler:completion];
}
- (BOOL)lc_guest_openURL:(NSURL *)url {
    return LCRouteGuestURL(url, nil) || [self lc_guest_openURL:url];
}
- (void)lc_guest_applicationOpenURLAction:(id)action payload:(NSDictionary *)payload origin:(id)origin {
    id value = payload[UIApplicationLaunchOptionsURLKey];
    NSURL *url = [value isKindOfClass:NSString.class] ? [NSURL URLWithString:value] : value;
    if (!url && [action isKindOfClass:UIOpenURLAction.class]) url = [action url];
    if ([url.scheme.lowercaseString isEqualToString:NSUserDefaults.lcAppUrlScheme.lowercaseString] && [url.host isEqualToString:@"guest-route"]) {
        NSString *source;
        NSURL *decoded = LCDecodeGuestURL(url, &source);
        if (!decoded) { LCRouteError(@"目标应用状态已变化，请返回原应用重试。"); return; }
        if ([url.absoluteString isEqualToString:NSUserDefaults.lcLaunchURL]) initialURLDelivered = YES;
        NSMutableDictionary *updated = payload.mutableCopy ?: [NSMutableDictionary new];
        updated[UIApplicationLaunchOptionsURLKey] = decoded.absoluteString;
        if (source) updated[UIApplicationLaunchOptionsSourceApplicationKey] = source;
        [self lc_guest_applicationOpenURLAction:[[UIOpenURLAction alloc] initWithURL:decoded] payload:updated origin:source ?: origin];
        return;
    }
    [self lc_guest_applicationOpenURLAction:action payload:payload origin:origin];
}
- (void)lc_guest_connectScene:(id)scene transitionContext:(UIApplicationSceneTransitionContext *)context {
    NSURL *url = nil;
    if (!initialURLDelivered && NSUserDefaults.lcLaunchURL) url = [NSURL URLWithString:NSUserDefaults.lcLaunchURL];
    initialURLDelivered = YES;
    id value = context.payload[UIApplicationLaunchOptionsURLKey];
    if (!url) url = [value isKindOfClass:NSString.class] ? [NSURL URLWithString:value] : value;
    if (!url) for (id action in context.actions) if ([action isKindOfClass:UIOpenURLAction.class]) { url = [action url]; break; }
    NSString *source;
    NSURL *decoded = LCDecodeGuestURL(url, &source);
    BOOL routing = [url.scheme.lowercaseString isEqualToString:NSUserDefaults.lcAppUrlScheme.lowercaseString] && [url.host isEqualToString:@"guest-route"];
    if (routing) {
        NSMutableDictionary *payload = context.payload.mutableCopy ?: [NSMutableDictionary new];
        [payload removeObjectForKey:UIApplicationLaunchOptionsURLKey];
        if (decoded) payload[UIApplicationLaunchOptionsURLKey] = url.absoluteString;
        if (source) payload[UIApplicationLaunchOptionsSourceApplicationKey] = source;
        context.payload = payload;
        NSMutableSet *actions = context.actions.mutableCopy ?: [NSMutableSet new];
        for (id action in context.actions) if ([action isKindOfClass:UIOpenURLAction.class]) [actions removeObject:action];
        // Keep the envelope until UIKit creates the URL context, where both URL and options are restored.
        if (decoded) [actions addObject:[[UIOpenURLAction alloc] initWithURL:url]];
        context.actions = actions;
        if (!decoded) dispatch_async(dispatch_get_main_queue(), ^{ LCRouteError(@"目标应用状态已变化，请返回原应用重试。"); });
    }
    [self lc_guest_connectScene:scene transitionContext:context];
}
@end

@implementation UIScene (LCGuestURLRouter)
- (void)lc_guest_openURL:(NSURL *)url options:(UISceneOpenExternalURLOptions *)options completionHandler:(void (^)(BOOL))completion {
    if (!LCRouteGuestURL(url, completion)) [self lc_guest_openURL:url options:options completionHandler:completion];
}
- (void)lc_guest_scene:(id)scene didReceiveActions:(NSSet *)actions fromTransitionContext:(id)context {
    NSMutableSet *updated = actions.mutableCopy;
    for (id action in actions) {
        if (![action isKindOfClass:UIOpenURLAction.class]) continue;
        NSURL *url = [action url];
        if (![url.scheme.lowercaseString isEqualToString:NSUserDefaults.lcAppUrlScheme.lowercaseString] || ![url.host isEqualToString:@"guest-route"]) continue;
        [updated removeObject:action];
        NSString *source;
        NSURL *decoded = LCDecodeGuestURL(url, &source);
        if (decoded) {
            if ([url.absoluteString isEqualToString:NSUserDefaults.lcLaunchURL]) initialURLDelivered = YES;
            [updated addObject:action];
        } else LCRouteError(@"目标应用状态已变化，请返回原应用重试。");
    }
    [self lc_guest_scene:scene didReceiveActions:updated fromTransitionContext:context];
}
@end

void LCGuestURLRouterInit(void) {
    if (!NSUserDefaults.lcGuestAppId || NSUserDefaults.isSideStore) return;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if ([LCDebugLog isEnabled]) {
            LCDebugLog(@"GuestURL", @"startup guest-url-r5 installed-targets build=%@ host=%@ guest=%@ iOS=%@ liveProcess=%d shared=%d tweakLoaderDisabled=%d", NSUserDefaults.lcMainBundle.infoDictionary[@"LCVersionInfo"], NSUserDefaults.lcAppUrlScheme, NSUserDefaults.lcGuestAppId, UIDevice.currentDevice.systemVersion, NSUserDefaults.isLiveProcess, NSUserDefaults.isSharedApp, [NSUserDefaults.guestAppInfo[@"dontLoadTweakLoader"] boolValue]);
            LCDebugLog(@"GuestURL", @"own schemes=%@", LCSchemes(NSBundle.mainBundle.infoDictionary));
            for (NSString *root in LCSharedGuestRoots()) {
                NSError *error;
                NSArray *names = [NSFileManager.defaultManager contentsOfDirectoryAtPath:root error:&error];
                LCDebugLog(@"GuestURL", @"scan root=%@ entries=%lu error=%@/%ld", root, (unsigned long)names.count, error.domain ?: @"none", (long)error.code);
                for (NSString *name in names) {
                    if (![name.pathExtension.lowercaseString isEqualToString:@"app"]) continue;
                    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[[root stringByAppendingPathComponent:name] stringByAppendingPathComponent:@"Info.plist"]];
                    LCDebugLog(@"GuestURL", @"installed bundle=%@ infoReadable=%d schemes=%@", name, info != nil, LCSchemes(info));
                }
            }
        }
        [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
            // Apps without scenes receive the same cold-start request through their AppDelegate.
            if (initialURLDelivered) return;
            NSString *source;
            NSURL *decoded = LCDecodeGuestURL([NSURL URLWithString:NSUserDefaults.lcLaunchURL ?: @""], &source);
            if (!decoded) return;
            initialURLDelivered = YES;
            UIApplication *application = UIApplication.sharedApplication;
            id<UIApplicationDelegate> delegate = application.delegate;
            if ([delegate respondsToSelector:@selector(application:openURL:options:)]) {
                [delegate application:application openURL:decoded options:source ? @{UIApplicationOpenURLOptionsSourceApplicationKey: source} : @{}];
            } else if ([delegate respondsToSelector:@selector(application:openURL:sourceApplication:annotation:)]) {
                [delegate application:application openURL:decoded sourceApplication:source annotation:NSNull.null];
            }
        }];
        for (NSArray *entry in @[
            @[UIOpenURLContext.class, @"URL", @"lc_guest_URL"],
            @[UIOpenURLContext.class, @"options", @"lc_guest_options"],
            @[UISceneOpenURLOptions.class, @"sourceApplication", @"lc_guest_sourceApplication"],
            @[UIApplication.class, @"canOpenURL:", @"lc_guest_canOpenURL:"],
            @[UIApplication.class, @"openURL:", @"lc_guest_openURL:"],
            @[UIApplication.class, @"openURL:options:completionHandler:", @"lc_guest_openURL:options:completionHandler:"],
            @[UIApplication.class, @"_applicationOpenURLAction:payload:origin:", @"lc_guest_applicationOpenURLAction:payload:origin:"],
            @[UIApplication.class, @"_connectUISceneFromFBSScene:transitionContext:", @"lc_guest_connectScene:transitionContext:"],
            @[UIScene.class, @"openURL:options:completionHandler:", @"lc_guest_openURL:options:completionHandler:"],
            @[UIScene.class, @"scene:didReceiveActions:fromTransitionContext:", @"lc_guest_scene:didReceiveActions:fromTransitionContext:"]]) {
            Class cls = entry[0]; SEL original = NSSelectorFromString(entry[1]);
            BOOL available = [cls instancesRespondToSelector:original];
            if (available) swizzle(cls, original, NSSelectorFromString(entry[2]));
            LCDebugLog(@"GuestURL", @"hook %@ %@ installed=%d", NSStringFromClass(cls), entry[1], available);
        }
    });
}
