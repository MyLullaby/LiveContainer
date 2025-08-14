//
//  NSUserDefaults.m
//  LiveContainer
//
//  Created by s s on 2024/11/29.
//

#import "FoundationPrivate.h"
#import "LCMachOUtils.h"
#import "LCSharedUtils.h"
#import "utils.h"
#import "../../litehook/src/litehook.h"
#include "Tweaks.h"
#import "CloudKit/CloudKit.h"
#import "Intents/Intents.h"
@import ObjectiveC;
@import MachO;

BOOL hook_return_false(void) {
    return NO;
}

void swizzle(Class class, SEL originalAction, SEL swizzledAction) {
    method_exchangeImplementations(class_getInstanceMethod(class, originalAction), class_getInstanceMethod(class, swizzledAction));
}

void swizzle2(Class class, SEL originalAction, Class class2, SEL swizzledAction) {
    Method m1 = class_getInstanceMethod(class2, swizzledAction);
    class_addMethod(class, swizzledAction, method_getImplementation(m1), method_getTypeEncoding(m1));
    method_exchangeImplementations(class_getInstanceMethod(class, originalAction), class_getInstanceMethod(class, swizzledAction));
}

void swizzleClassMethod(Class class, SEL originalAction, SEL swizzledAction) {
    method_exchangeImplementations(class_getClassMethod(class, originalAction), class_getClassMethod(class, swizzledAction));
}

NSURL* appContainerURL = 0;
NSString* appContainerPath = 0;

void NUDGuestHooksInit(void) {
    appContainerPath = [NSString stringWithUTF8String:getenv("HOME")];
    appContainerURL = [NSURL URLWithString:appContainerPath];
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundeclared-selector"
    
#if TARGET_OS_MACCATALYST || TARGET_OS_SIMULATOR
    // fix for macOS host
    method_setImplementation(class_getInstanceMethod(NSClassFromString(@"CFPrefsPlistSource"), @selector(_isSharedInTheiOSSimulator)), (IMP)hook_return_false);
#endif

    Class CFPrefsPlistSourceClass = NSClassFromString(@"CFPrefsPlistSource");

    swizzle2(CFPrefsPlistSourceClass, @selector(initWithDomain:user:byHost:containerPath:containingPreferences:), CFPrefsPlistSource2.class, @selector(hook_initWithDomain:user:byHost:containerPath:containingPreferences:));
    
    // 处理iCloud
    swizzleClassMethod(CKContainer.class, @selector(defaultContainer), @selector(hook_defaultContainer));
    swizzleClassMethod(CKContainer.class, @selector(containerWithIdentifier:),@selector(hook_containerWithIdentifier:));
    // 处理Siri
    swizzleClassMethod(INPreferences.class, @selector(requestSiriAuthorization:),@selector(hook_requestSiriAuthorization:));
    swizzleClassMethod(INPreferences.class, @selector(siriAuthorizationStatus),@selector(hook_siriAuthorizationStatus));
    swizzleClassMethod(INVocabulary.class, @selector(sharedVocabulary),@selector(hook_sharedVocabulary));
    swizzleClassMethod(INPlayMediaIntent.class, @selector(initWithMediaItems:mediaItems:mediaContainer:playShuffled:playbackRepeatMode:resumePlayback:playbackQueueLocation:playbackSpeed:mediaSearch:),@selector(hook_initWithMediaItems:mediaItems:mediaContainer:playShuffled:playbackRepeatMode:resumePlayback:playbackQueueLocation:playbackSpeed:mediaSearch:));

#pragma clang diagnostic pop
    
    Class CFXPreferencesClass = NSClassFromString(@"_CFXPreferences");
    NSMutableDictionary* sources = object_getIvar([CFXPreferencesClass copyDefaultPreferences], class_getInstanceVariable(CFXPreferencesClass, "_sources"));

    [sources removeObjectForKey:@"C/A//B/L"];
    [sources removeObjectForKey:@"C/C//*/L"];
    
    // replace _CFPrefsCurrentAppIdentifierCache so kCFPreferencesCurrentApplication refers to the guest app
    const char* coreFoundationPath = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    mach_header_u* coreFoundationHeader = LCGetLoadedImageHeader(2, coreFoundationPath);
    
#if !TARGET_OS_SIMULATOR
    CFStringRef* _CFPrefsCurrentAppIdentifierCache = getCachedSymbol(@"__CFPrefsCurrentAppIdentifierCache", coreFoundationHeader);
    if(!_CFPrefsCurrentAppIdentifierCache) {
        _CFPrefsCurrentAppIdentifierCache = litehook_find_dsc_symbol(coreFoundationPath, "__CFPrefsCurrentAppIdentifierCache");
        uint64_t offset = (uint64_t)((void*)_CFPrefsCurrentAppIdentifierCache - (void*)coreFoundationHeader);
        saveCachedSymbol(@"__CFPrefsCurrentAppIdentifierCache", coreFoundationHeader, offset);
    }
    [NSUserDefaults.lcUserDefaults _setIdentifier:(__bridge NSString*)CFStringCreateCopy(nil, *_CFPrefsCurrentAppIdentifierCache)];
    *_CFPrefsCurrentAppIdentifierCache = (__bridge CFStringRef)NSUserDefaults.lcGuestAppId;
#else
    // FIXME: for now we skip overwriting _CFPrefsCurrentAppIdentifierCache on simulator, since there is no way to find private symbol
#endif
    
    NSUserDefaults* newStandardUserDefaults = [[NSUserDefaults alloc] initWithSuiteName:@"whatever"];
    [newStandardUserDefaults _setIdentifier:NSUserDefaults.lcGuestAppId];
    NSUserDefaults.standardUserDefaults = newStandardUserDefaults;

#if !TARGET_OS_SIMULATOR
    NSString* selectedLanguage = NSUserDefaults.guestAppInfo[@"LCSelectedLanguage"];
    if(selectedLanguage) {
        [newStandardUserDefaults setObject:@[selectedLanguage] forKey:@"AppleLanguages"];
        CFMutableArrayRef* _CFBundleUserLanguages = getCachedSymbol(@"__CFBundleUserLanguages", coreFoundationHeader);
        if(!_CFBundleUserLanguages) {
            _CFBundleUserLanguages = litehook_find_dsc_symbol(coreFoundationPath, "__CFBundleUserLanguages");
            uint64_t offset = (uint64_t)((void*)_CFBundleUserLanguages - (void*)coreFoundationHeader);
            saveCachedSymbol(@"__CFBundleUserLanguages", coreFoundationHeader, offset);
        }
        // set _CFBundleUserLanguages to selected languages
        NSMutableArray* newUserLanguages = [NSMutableArray arrayWithObjects:selectedLanguage, nil];
        *_CFBundleUserLanguages = (__bridge CFMutableArrayRef)newUserLanguages;
    } else {
        [newStandardUserDefaults removeObjectForKey:@"AppleLanguages"];
    }
#endif
    
    // Create Library/Preferences folder in app's data folder in case it does not exist
    NSFileManager* fm = NSFileManager.defaultManager;
    NSURL* libraryPath = [fm URLsForDirectory:NSLibraryDirectory inDomains:NSUserDomainMask].lastObject;
    NSURL* preferenceFolderPath = [libraryPath URLByAppendingPathComponent:@"Preferences"];
    if(![fm fileExistsAtPath:preferenceFolderPath.path]) {
        NSError* error;
        [fm createDirectoryAtPath:preferenceFolderPath.path withIntermediateDirectories:YES attributes:@{} error:&error];
    }

}

NSArray* appleIdentifierPrefixes = @[
    @"com.apple.",
    @"group.com.apple.",
    @"systemgroup.com.apple."
];

bool isAppleIdentifier(NSString* identifier) {
    for(NSString* cur in appleIdentifierPrefixes) {
        if([identifier hasPrefix:cur]) {
            return true;
        }
    }
    return false;
}


@implementation CFPrefsPlistSource2
-(id)hook_initWithDomain:(CFStringRef)domain user:(CFStringRef)user byHost:(bool)host containerPath:(CFStringRef)containerPath containingPreferences:(id)arg5 {
    if(isAppleIdentifier((__bridge NSString*)domain)) {
        return [self hook_initWithDomain:domain user:user byHost:host containerPath:containerPath containingPreferences:arg5];
    }
    return [self hook_initWithDomain:domain user:user byHost:host containerPath:(__bridge CFStringRef)appContainerPath containingPreferences:arg5];
}
@end

@implementation INPreferences (hook)
+ (void)hook_requestSiriAuthorization:(void (^)(INSiriAuthorizationStatus))handler {
    NSLog(@"Swizzled requestSiriAuthorization, denying access");
    if (handler) {
        handler(INSiriAuthorizationStatusDenied);
    }
}
+ (INSiriAuthorizationStatus)hook_siriAuthorizationStatus {
    NSLog(@"Swizzled requestSiriAuthorization, denying access");
    return INSiriAuthorizationStatusDenied;
}
@end

@implementation CKContainer (hook)
- (void)hook_accountStatusWithCompletionHandler:(void (^)(CKAccountStatus, NSError *))completionHandler {
    NSLog(@"Swizzled accountStatusWithCompletionHandler, denying iCloud access");
    if (completionHandler) {
        // 返回无账户状态，模拟 iCloud 不可用
        completionHandler(CKAccountStatusNoAccount, [NSError errorWithDomain:@"CloudKit" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"iCloud access denied"}]);
    }
}
+ (CKContainer *)hook_defaultContainer {
    NSLog(@"Swizzled swizzled_defaultContainer, denying iCloud access");
    return nil;
}
+ (CKContainer *)hook_containerWithIdentifier:(NSString *)containerIdentifier {
    NSLog(@"Swizzled swizzled_containerWithIdentifier, denying iCloud access");
    return nil;
}
// 阻止用户获取令牌
- (void)hook_fetchUserRecordIDWithCompletionHandler:(void (^)(CKRecordID *recordID, NSError *error))completionHandler {
    // 返回虚假信息
    if (completionHandler) {
        NSError *error = [NSError errorWithDomain:CKErrorDomain
                                             code:CKErrorNotAuthenticated
                                         userInfo:@{NSLocalizedDescriptionKey: @"User authentication failed"}];
        completionHandler(nil, error);
    }
}
// 阻止权限检查
- (void)hook_requestApplicationPermission:(CKApplicationPermissions)permission completionHandler:(void (^)(CKApplicationPermissionStatus status, NSError *error))completion {
    // 总是返回无权限状态
    if (completion) {
        NSError *error = [NSError errorWithDomain:CKErrorDomain
                                             code:CKErrorPermissionFailure
                                         userInfo:@{NSLocalizedDescriptionKey: @"iCloud access denied"}];
        completion(CKApplicationPermissionStatusDenied, error);
    }
}
@end

@implementation NSFileManager (hook)
// 阻止文件令牌获取访问
- (id)alwaysDenyUbiquityIdentityToken {
    return nil; // 返回nil阻止文件同步
}
@end

@implementation INVocabulary (hook)

+ (instancetype)hook_sharedVocabulary {
    return nil;
}

@end


@implementation INPlayMediaIntent (hook)

- (instancetype)hook_initWithMediaItems:(nullable NSArray<INMediaItem *> *)mediaItems
                    mediaContainer:(nullable INMediaItem *)mediaContainer
                      playShuffled:(nullable NSNumber *)playShuffled
                playbackRepeatMode:(INPlaybackRepeatMode)playbackRepeatMode
                    resumePlayback:(nullable NSNumber *)resumePlayback
             playbackQueueLocation:(INPlaybackQueueLocation)playbackQueueLocation
                     playbackSpeed:(nullable NSNumber *)playbackSpeed
                       mediaSearch:(nullable INMediaSearch *)mediaSearch {
    return nil;
}

@end

@implementation CKDatabase (hook)
- (void)hook_fetchRecordWithID:(CKRecordID *)recordID completionHandler:(void (NS_SWIFT_SENDABLE ^)(CKRecord * _Nullable record, NSError * _Nullable error))completionHandler {
    if (completionHandler) {
        NSError *error = [NSError errorWithDomain:CKErrorDomain
                                             code:CKErrorPermissionFailure
                                         userInfo:@{NSLocalizedDescriptionKey: @"iCloud access denied"}];
        completionHandler(nil, error);
    }
}
- (void)hook_performQuery:(CKQuery *)query inZoneWithID:(nullable CKRecordZoneID *)zoneID completionHandler:(void (NS_SWIFT_SENDABLE ^)(NSArray<CKRecord *> * _Nullable results, NSError * _Nullable error))completionHandler {
    if (completionHandler) {
        NSError *error = [NSError errorWithDomain:CKErrorDomain
                                             code:CKErrorPermissionFailure
                                         userInfo:@{NSLocalizedDescriptionKey: @"iCloud access denied"}];
        completionHandler(nil, error);
    }
}
@end
