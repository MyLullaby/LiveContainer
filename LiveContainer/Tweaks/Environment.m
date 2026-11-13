#import "../utils.h"
#import "../../litehook/src/litehook.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

static const char *const hiddenVariables[] = {
    "LC_HOME_PATH", "LP_HOME_PATH", "LC_GLOBAL_TWEAKS_FOLDER", "LC_JITLESS_TEST_LOADED"
};
static NSString *hostBundlePath;
static char *(*originalGetenv)(const char *) = getenv;
static NSDictionary *(*originalEnvironment)(id, SEL);

static BOOL isHostCaller(const void *caller) {
    Dl_info info = {};
    if (!dladdr(caller, &info) || !info.dli_fname) return NO;
    const char *path = info.dli_fname;
    if (!strncmp(path, "/private/", 9)) path += 8;
    const char *prefix = hostBundlePath.fileSystemRepresentation;
    return !strncmp(path, prefix, strlen(prefix));
}

static char *hookGetenv(const char *name) {
    for (NSUInteger i = 0; i < sizeof(hiddenVariables) / sizeof(*hiddenVariables); i++) {
        if (!strcmp(name, hiddenVariables[i]) && !isHostCaller(__builtin_return_address(0))) return NULL;
    }
    return originalGetenv(name);
}

static NSDictionary *hookEnvironment(id self, SEL selector) {
    NSDictionary *environment = originalEnvironment(self, selector);
    if (isHostCaller(__builtin_return_address(0))) return environment;
    NSMutableDictionary *filtered = environment.mutableCopy;
    for (NSUInteger i = 0; i < sizeof(hiddenVariables) / sizeof(*hiddenVariables); i++) {
        [filtered removeObjectForKey:@(hiddenVariables[i])];
    }
    return filtered.copy;
}

void EnvironmentGuestHooksInit(bool hideLiveContainer) {
    if (!hideLiveContainer) return;
    NSString *bundlePath = NSUserDefaults.lcMainBundle.bundlePath.stringByResolvingSymlinksInPath;
    if ([bundlePath.pathExtension isEqualToString:@"appex"]) {
        bundlePath = bundlePath.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
    }
    hostBundlePath = [bundlePath stringByAppendingString:@"/"];
    if ([hostBundlePath hasPrefix:@"/private/"]) hostBundlePath = [hostBundlePath substringFromIndex:8];

    // Preserve the real environment for LC and its bundled helpers, including TweakLoader.
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, getenv, hookGetenv, nil);
    // shortcut: API queries only; migrate host state before hiding direct environ access.
    Method method = class_getInstanceMethod(NSProcessInfo.class, @selector(environment));
    originalEnvironment = (void *)method_getImplementation(method);
    method_setImplementation(method, (IMP)hookEnvironment);
    Class swiftProcessInfo = NSClassFromString(@"_NSSwiftProcessInfo");
    if (swiftProcessInfo) {
        // Match the existing arguments hook: Swift reads the same environment as ObjC.
        if (!class_addMethod(swiftProcessInfo, @selector(environment), (IMP)hookEnvironment, method_getTypeEncoding(method))) {
            method_setImplementation(class_getInstanceMethod(swiftProcessInfo, @selector(environment)), (IMP)hookEnvironment);
        }
    }
}
