#import "LCGuestURLRouter.h"
#import "LCSharedUtils.h"
#import "UIKitPrivate.h"
#import "utils.h"
#import "Tweaks.h"
#import <LocalAuthentication/LocalAuthentication.h>

// shortcut: Keep one callback target for 15 minutes; track requests separately if concurrent login flows are needed.
static NSDictionary *returnTarget;
static NSDate *returnDate;
static BOOL initialURLDelivered;

static void LCGuestURLLog(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
static void LCGuestURLLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSString *key = [@"LCGuestURLDiagnostics." stringByAppendingString:NSBundle.mainBundle.bundlePath.lastPathComponent];
    @synchronized (LCGuestURLRouter.class) {
        NSMutableArray *lines = [[NSUserDefaults.lcSharedDefaults arrayForKey:key] mutableCopy] ?: [NSMutableArray new];
        [lines addObject:[NSString stringWithFormat:@"%@ %@", NSDate.date, message]];
        if (lines.count > 100) [lines removeObjectsInRange:NSMakeRange(0, lines.count - 100)];
        [NSUserDefaults.lcSharedDefaults setObject:lines forKey:key];
    }
    NSLog(@"[LC][GuestURL] %@", message);
}

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

static NSDictionary *LCTargetForURL(NSURL *url) {
    NSString *scheme = url.scheme.lowercaseString;
    if (!LCIsGuestScheme(scheme)) return nil;
    if ([LCSchemes(NSBundle.mainBundle.infoDictionary) containsObject:scheme]) {
        LCGuestURLLog(@"resolve scheme=%@ result=self", scheme);
        return nil;
    }
    BOOL returning = returnTarget && -returnDate.timeIntervalSinceNow < 900 && [returnTarget[@"schemes"] containsObject:scheme] &&
        [LCSharedUtils getContainerUsingLCSchemeWithFolderName:returnTarget[@"container"]];
    NSString *shared = [[[[LCSharedUtils appGroupPath] path] stringByAppendingPathComponent:@"LiveContainer/Applications"] stringByResolvingSymlinksInPath];
    NSMutableArray *matches = [NSMutableArray new];
    for (NSString *root in LCGuestRoots()) {
        for (NSString *name in [[NSFileManager.defaultManager contentsOfDirectoryAtPath:root error:nil] sortedArrayUsingSelector:@selector(compare:)]) {
            NSString *path = [root stringByAppendingPathComponent:name];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
            if (![LCSchemes(info) containsObject:scheme]) continue;
            NSDictionary *settings = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"LCAppInfo.plist"]];
            if ([settings[@"isHidden"] boolValue] && [NSUserDefaults.lcSharedDefaults boolForKey:@"LCStrictHiding"]) {
                LCGuestURLLog(@"resolve scheme=%@ excluded=strict-hidden bundle=%@", scheme, name);
                continue;
            }
            NSString *container = settings[@"LCDataUUID"];
            NSMutableArray *containers = [NSMutableArray new];
            if (container) [containers addObject:container];
            for (NSDictionary *entry in settings[@"LCContainers"]) {
                NSString *folder = entry[@"folderName"];
                if (folder && ![containers containsObject:folder]) [containers addObject:folder];
            }
            NSMutableArray *running = [NSMutableArray new];
            for (NSString *folder in containers) {
                if ([LCSharedUtils getContainerUsingLCSchemeWithFolderName:folder]) [running addObject:folder];
            }
            // A reply goes back to the initiating container, including apps with multiple accounts.
            BOOL isReturnTarget = returning && [returnTarget[@"bundle"] isEqualToString:name] && [containers containsObject:returnTarget[@"container"]];
            if (isReturnTarget) container = returnTarget[@"container"];
            else if (running.count == 1) container = running.firstObject;
            if (!container) container = containers.firstObject ?: @"";
            if (!isReturnTarget && running.count > 1) {
                LCGuestURLLog(@"resolve scheme=%@ excluded=multiple-running-containers bundle=%@", scheme, name);
                continue;
            }
            [matches addObject:@{@"bundle": name, @"container": container, @"shared": @([root isEqualToString:shared]),
                                 @"locked": @([settings[@"isLocked"] boolValue] || [settings[@"isHidden"] boolValue])}];
        }
    }
    if (returning) {
        for (NSDictionary *target in matches) {
            if ([target[@"bundle"] isEqualToString:returnTarget[@"bundle"]] && [target[@"container"] isEqualToString:returnTarget[@"container"]]) {
                LCGuestURLLog(@"resolve scheme=%@ result=callback bundle=%@", scheme, target[@"bundle"]);
                return target;
            }
        }
    }
    // Do not silently choose between different apps registering the same scheme.
    LCGuestURLLog(@"resolve scheme=%@ matches=%lu bundles=%@", scheme, (unsigned long)matches.count, [matches valueForKey:@"bundle"]);
    return matches.count == 1 ? matches.firstObject : nil;
}

static void LCRouteError(NSString *message) {
    NSLog(@"[LC][GuestURL] %@", message);
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
+ (NSString *)diagnosticsForBundleName:(NSString *)bundleName {
    NSArray *lines = [NSUserDefaults.lcSharedDefaults arrayForKey:[@"LCGuestURLDiagnostics." stringByAppendingString:bundleName]];
    return lines.count ? [lines componentsJoinedByString:@"\n"] : @"暂无诊断记录。请使用包含诊断功能的 LC 完全退出并重新启动此应用，再复现一次。";
}
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
    if (!LCValidComponent(bundle) || !container || (container.length && !LCValidComponent(container)) ||
        !original.length || !LCIsGuestScheme([NSURL URLWithString:original].scheme)) return nil;
    values[@"url"] = original;
    return values;
}
@end

static void LCSendGuestURL(NSURL *url, NSDictionary *target, void (^completion)(BOOL)) {
    NSString *running = [target[@"container"] length] ? [LCSharedUtils getContainerUsingLCSchemeWithFolderName:target[@"container"]] : nil;
    NSString *destination = running.stringByDeletingPathExtension;
    // Older hosts record only their scheme for LiveProcess; the host UI can still deliver to the existing window.
    BOOL multitask = [running hasSuffix:@".liveprocess"] || (NSUserDefaults.isLiveProcess && [destination isEqualToString:NSUserDefaults.lcAppUrlScheme]);
    if (!destination) {
        for (NSString *scheme in [LCSharedUtils lcUrlSchemes]) {
            if ([scheme isEqualToString:NSUserDefaults.lcAppUrlScheme] || ![target[@"shared"] boolValue]) continue;
            if (![LCSharedUtils isLCSchemeInUse:scheme] && [UIApplication.sharedApplication canOpenURL:[NSURL URLWithString:[scheme stringByAppendingString:@"://"]]]) {
                destination = scheme;
                break;
            }
        }
        if (!destination && NSUserDefaults.isLiveProcess) {
            destination = NSUserDefaults.lcAppUrlScheme;
            multitask = YES;
        }
    }
    if (!destination) {
        LCRouteError(@"没有可用的 LiveContainer 承接目标应用。请将目标应用设为共享，并准备一个空闲 LC2/LC3，或使用多任务模式；当前应用会保持运行。");
        LCGuestURLLog(@"send scheme=%@ bundle=%@ result=no-free-host", url.scheme.lowercaseString, target[@"bundle"]);
        if (completion) completion(NO);
        return;
    }
    NSURLComponents *control = [NSURLComponents new];
    control.scheme = destination;
    control.host = @"guest-route";
    NSMutableArray *query = [NSMutableArray arrayWithArray:@[
        [NSURLQueryItem queryItemWithName:@"bundle-name" value:target[@"bundle"]],
        [NSURLQueryItem queryItemWithName:@"container-folder-name" value:target[@"container"]],
        [NSURLQueryItem queryItemWithName:@"open-url" value:[[url.absoluteString dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0]],
        [NSURLQueryItem queryItemWithName:@"multitask" value:multitask ? @"1" : @"0"],
        [NSURLQueryItem queryItemWithName:@"source-bundle" value:NSBundle.mainBundle.bundlePath.lastPathComponent],
        [NSURLQueryItem queryItemWithName:@"source-container" value:@(getenv("HOME")).lastPathComponent]]];
    control.queryItems = query;
    LCGuestURLLog(@"send scheme=%@ bundle=%@ destination=%@ multitask=%d", url.scheme.lowercaseString, target[@"bundle"], destination, multitask);
    [UIApplication.sharedApplication openURL:control.URL options:@{} completionHandler:completion];
}

static BOOL LCRouteGuestURL(NSURL *url, void (^completion)(BOOL)) {
    LCGuestURLLog(@"openURL scheme=%@", url.scheme.lowercaseString ?: @"(none)");
    NSDictionary *target = LCTargetForURL(url);
    if (!target) return NO;
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([target[@"locked"] boolValue]) {
            LAContext *context = [LAContext new];
            [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication localizedReason:@"打开 LC 内的应用" reply:^(BOOL success, NSError *error) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (success) LCSendGuestURL(url, target, completion);
                    else if (completion) completion(NO);
                });
            }];
        } else LCSendGuestURL(url, target, completion);
    });
    return YES;
}

static NSURL *LCDecodeGuestURL(NSURL *url, NSString **source) {
    NSDictionary *request = [LCGuestURLRouter requestForURL:url];
    if (!request) return nil;
    NSURL *original = [NSURL URLWithString:request[@"url"]];
    if (![request[@"bundle-name"] isEqualToString:NSBundle.mainBundle.bundlePath.lastPathComponent] ||
        ([request[@"container-folder-name"] length] && ![request[@"container-folder-name"] isEqualToString:@(getenv("HOME")).lastPathComponent]) ||
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
    if (sourceBundle && [LCSharedUtils getContainerUsingLCSchemeWithFolderName:fromContainer]) {
        returnTarget = @{@"bundle": fromBundle, @"container": fromContainer,
                         @"schemes": LCSchemes(sourceBundle.infoDictionary),
                         @"identifier": settings[@"LCOrignalBundleIdentifier"] ?: sourceBundle.bundleIdentifier ?: @""};
        returnDate = NSDate.date;
        *source = returnTarget[@"identifier"];
    }
    return original;
}

@implementation UIApplication (LCGuestURLRouter)
- (BOOL)lc_guest_canOpenURL:(NSURL *)url {
    BOOL routed = [LCGuestURLRouter canRouteURL:url];
    BOOL result = routed || [self lc_guest_canOpenURL:url];
    if (LCIsGuestScheme(url.scheme)) LCGuestURLLog(@"canOpenURL scheme=%@ guest=%d result=%d", url.scheme.lowercaseString, routed, result);
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
        if (decoded) payload[UIApplicationLaunchOptionsURLKey] = decoded.absoluteString;
        if (source) payload[UIApplicationLaunchOptionsSourceApplicationKey] = source;
        context.payload = payload;
        NSMutableSet *actions = context.actions.mutableCopy ?: [NSMutableSet new];
        for (id action in context.actions) if ([action isKindOfClass:UIOpenURLAction.class]) [actions removeObject:action];
        if (decoded) [actions addObject:[[UIOpenURLAction alloc] initWithURL:decoded]];
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
            [updated addObject:[[UIOpenURLAction alloc] initWithURL:decoded]];
        } else LCRouteError(@"目标应用状态已变化，请返回原应用重试。");
    }
    [self lc_guest_scene:scene didReceiveActions:updated fromTransitionContext:context];
}
@end

void LCGuestURLRouterInit(void) {
    if (!NSUserDefaults.lcGuestAppId || NSUserDefaults.isSideStore) return;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        LCGuestURLLog(@"startup guest-url-r2 build=%@ host=%@ guest=%@ iOS=%@ liveProcess=%d shared=%d strictHiding=%d tweakLoaderDisabled=%d", NSUserDefaults.lcMainBundle.infoDictionary[@"LCVersionInfo"], NSUserDefaults.lcAppUrlScheme, NSUserDefaults.lcGuestAppId, UIDevice.currentDevice.systemVersion, NSUserDefaults.isLiveProcess, NSUserDefaults.isSharedApp, [NSUserDefaults.lcSharedDefaults boolForKey:@"LCStrictHiding"], [NSUserDefaults.guestAppInfo[@"dontLoadTweakLoader"] boolValue]);
        LCGuestURLLog(@"own schemes=%@", LCSchemes(NSBundle.mainBundle.infoDictionary));
        for (NSString *root in LCGuestRoots()) {
            NSError *error;
            NSArray *names = [NSFileManager.defaultManager contentsOfDirectoryAtPath:root error:&error];
            LCGuestURLLog(@"scan root=%@ entries=%lu error=%@/%ld", root, (unsigned long)names.count, error.domain ?: @"none", (long)error.code);
            for (NSString *name in names) {
                if (![name.pathExtension.lowercaseString isEqualToString:@"app"]) continue;
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[[root stringByAppendingPathComponent:name] stringByAppendingPathComponent:@"Info.plist"]];
                LCGuestURLLog(@"installed bundle=%@ infoReadable=%d schemes=%@", name, info != nil, LCSchemes(info));
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
            LCGuestURLLog(@"hook %@ %@ installed=%d", NSStringFromClass(cls), entry[1], available);
        }
    });
}
