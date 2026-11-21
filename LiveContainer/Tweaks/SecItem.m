//
//  SecItem.m
//  LiveContainer
//
//  Created by s s on 2024/11/29.
//
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "utils.h"
#import <CommonCrypto/CommonDigest.h>
#import "../../litehook/src/litehook.h"
#import "LCSharedUtils.h"
#import "LCManagedKeychain.h"
#import "LCDebugLog.h"
#include <dlfcn.h>

extern void* (*msHookFunction)(void *symbol, void *hook, void **old);
OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result) = SecItemAdd;
OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result) = SecItemCopyMatching;
OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) = SecItemUpdate;
OSStatus (*orig_SecItemDelete)(CFDictionaryRef query) = SecItemDelete;
SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef parameters, CFErrorRef *error) = SecKeyCreateRandomKey;
SecKeyRef (*orig_SecKeyCreateWithData)(CFDataRef keyData, CFDictionaryRef parameters, CFErrorRef *error) = SecKeyCreateWithData;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
OSStatus (*orig_SecKeyGeneratePair)(CFDictionaryRef query, SecKeyRef *publicKey, SecKeyRef *privateKey) = SecKeyGeneratePair;
#pragma clang diagnostic pop
NSString* accessGroup = nil;
NSString* containerId = nil;

static NSURL *managedKeychainDirectory;
static NSString *managedKeychainBundleRoot;
static LCKeychainMigration *managedKeychainMigration;
static NSString *managedLegacyGroup;
static NSString *managedLegacyAlias;

static bool LCManagedKeychainGuestImage(const mach_header_u *header) {
    Dl_info info = {};
    if (!dladdr(header, &info) || !info.dli_fname) return false;
    NSString *path = [@(info.dli_fname) stringByResolvingSymlinksInPath];
    return [path hasPrefix:managedKeychainBundleRoot];
}

#define KC(key) ((__bridge NSString *)key)

static NSDictionary *LCManagedSystemScope(NSDictionary *selector) {
    NSMutableDictionary *query = selector.mutableCopy;
    query[KC(kSecAttrAccessGroup)] = managedLegacyGroup;
    query[@"alis"] = managedLegacyAlias;
    query[KC(kSecAttrSynchronizable)] = @NO;
    return query;
}

static OSStatus LCManagedSystemFind(NSDictionary *selector, BOOL includeData, NSArray<NSDictionary *> **records) {
    NSString *itemClass = selector[KC(kSecClass)];
    NSData *reference = selector[KC(kSecValuePersistentRef)];
    NSMutableDictionary *query = reference ? [@{KC(kSecValuePersistentRef): reference} mutableCopy] : LCManagedSystemScope(selector).mutableCopy;
    query[KC(kSecMatchLimit)] = reference || includeData ? KC(kSecMatchLimitOne) : KC(kSecMatchLimitAll);
    query[KC(kSecReturnAttributes)] = @YES;
    query[KC(kSecReturnPersistentRef)] = @YES;
    if (includeData) query[KC(kSecReturnData)] = @YES;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    query[KC(kSecUseAuthenticationUI)] = KC(kSecUseAuthenticationUIFail);
#pragma clang diagnostic pop
    CFTypeRef output = NULL;
    OSStatus status = orig_SecItemCopyMatching((__bridge CFDictionaryRef)query, &output);
    id value = CFBridgingRelease(output);
    if (status != errSecSuccess) return status;
    NSArray *matches = [value isKindOfClass:NSDictionary.class] ? @[value] : value;
    if (![matches isKindOfClass:NSArray.class]) return errSecDecode;
    NSMutableArray *owned = [NSMutableArray arrayWithCapacity:matches.count];
    NSData *aliasData = [managedLegacyAlias dataUsingEncoding:NSUTF8StringEncoding];
    for (id entry in matches) {
        if (![entry isKindOfClass:NSDictionary.class]) return errSecDecode;
        NSDictionary *record = entry;
        id alias = record[@"alis"];
        id resultClass = record[KC(kSecClass)];
        id resultRef = record[KC(kSecValuePersistentRef)];
        if ((![alias isEqual:managedLegacyAlias] && ![alias isEqual:aliasData]) ||
            ![record[KC(kSecAttrAccessGroup)] isEqual:managedLegacyGroup] ||
            ![record[KC(kSecAttrSynchronizable)] isEqual:@NO] || (resultClass && ![resultClass isEqual:itemClass]) ||
            (reference && ![resultRef isEqual:reference])) {
            LCKeychainLogMessage(@"migration-scope", itemClass, errSecMissingEntitlement, @"system-ownership-unverified");
            return errSecMissingEntitlement;
        }
        if (![resultRef isKindOfClass:NSData.class] || ![resultRef length]) return errSecDecode;
        if (includeData) {
            id protection = record[KC(kSecAttrAccessible)];
            id accessControl = record[KC(kSecAttrAccessControl)];
            BOOL ordinaryProtection = [protection isEqual:KC(kSecAttrAccessibleWhenUnlocked)] ||
                [protection isEqual:KC(kSecAttrAccessibleAfterFirstUnlock)];
            id ordinaryACL = ordinaryProtection ? CFBridgingRelease(SecAccessControlCreateWithFlags(NULL,
                (__bridge CFTypeRef)protection, 0, NULL)) : nil;
            if (!ordinaryACL || ![ordinaryACL isEqual:accessControl] || record[KC(kSecAttrTokenID)]) {
                LCKeychainLogMessage(@"legacy-read", itemClass, errSecUnimplemented, @"legacy-protection-not-portable");
                return errSecUnimplemented;
            }
        }
        NSMutableDictionary *candidate = record.mutableCopy;
        [candidate removeObjectsForKeys:@[@"alis", KC(kSecAttrAccessControl), KC(kSecAttrAccessGroup)]];
        candidate[KC(kSecClass)] = itemClass;
        [owned addObject:candidate];
    }
    *records = owned;
    return owned.count ? errSecSuccess : errSecItemNotFound;
}

static OSStatus LCManagedSystemRemove(NSString *itemClass, NSData *reference) {
    NSDictionary *referenceQuery = @{KC(kSecClass): itemClass, KC(kSecValuePersistentRef): reference};
    NSArray *records = nil;
    OSStatus status = LCManagedSystemFind(referenceQuery, NO, &records);
    if (status != errSecSuccess) return status;
    NSMutableDictionary *query = LCManagedSystemScope(referenceQuery).mutableCopy;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    query[KC(kSecUseAuthenticationUI)] = KC(kSecUseAuthenticationUIFail);
#pragma clang diagnostic pop
    status = orig_SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess && status != errSecItemNotFound) return status;
    status = LCManagedSystemFind(referenceQuery, NO, &records);
    if (status == errSecItemNotFound) return errSecSuccess;
    return status == errSecSuccess ? errSecNotAvailable : status;
}

static OSStatus LCManagedAdd(CFDictionaryRef input, CFTypeRef *result) {
    return LCManagedKeychainPerformMigrating(managedKeychainDirectory, managedKeychainMigration, LCKeychainAdd, input, NULL, result);
}

static OSStatus LCManagedCopy(CFDictionaryRef input, CFTypeRef *result) {
    return LCManagedKeychainPerformMigrating(managedKeychainDirectory, managedKeychainMigration, LCKeychainCopy, input, NULL, result);
}

static OSStatus LCManagedUpdate(CFDictionaryRef input, CFDictionaryRef updates) {
    return LCManagedKeychainPerformMigrating(managedKeychainDirectory, managedKeychainMigration, LCKeychainUpdate, input, updates, NULL);
}

static OSStatus LCManagedDelete(CFDictionaryRef input) {
    return LCManagedKeychainPerformMigrating(managedKeychainDirectory, managedKeychainMigration, LCKeychainDelete, input, NULL, NULL);
}

static SecKeyRef LCManagedRandomKey(CFDictionaryRef parameters, CFErrorRef *error) {
    return LCManagedCreateRandomKey(managedKeychainDirectory, parameters, error);
}

static OSStatus LCManagedKeyPair(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey) {
    return LCManagedGenerateKeyPair(managedKeychainDirectory, parameters, publicKey, privateKey);
}

NSURL *LCManagedKeychainActiveDirectory(void) {
    return managedKeychainDirectory;
}

BOOL LCManagedKeychainHooksInit(NSString *bundlePath, NSString *containerPath, NSURL *store, NSString *legacyAlias) {
    if (!bundlePath.isAbsolutePath || !containerPath.isAbsolutePath || !store.isFileURL || !store.path.isAbsolutePath) {
        LCKeychainLogMessage(@"init", @"none", errSecParam, @"invalid-guest-path");
        return NO;
    }
    managedKeychainBundleRoot = [bundlePath.stringByResolvingSymlinksInPath stringByAppendingString:@"/"];
    managedKeychainDirectory = store;
    managedKeychainMigration = [LCKeychainMigration new];
    managedKeychainMigration.oldDirectory = [NSURL fileURLWithPath:[containerPath stringByAppendingPathComponent:@"Library/LCManagedKeychain"] isDirectory:YES];
    id legacyGroupID = [NSUserDefaults guestContainerInfo][@"keychainGroupId"];
    NSString *team = LCSharedUtils.teamIdentifier;
    if (legacyAlias.length && [legacyGroupID isKindOfClass:NSNumber.class] && [legacyGroupID integerValue] >= 0 && team.length) {
        NSInteger group = [legacyGroupID integerValue];
        NSString *base = [team stringByAppendingString:@".com.kdt.livecontainer.shared"];
        managedLegacyGroup = group ? [base stringByAppendingFormat:@".%ld", (long)group] : base;
        managedLegacyAlias = legacyAlias;
        managedKeychainMigration.systemFind = ^OSStatus(NSDictionary *selector, BOOL includeData, NSArray<NSDictionary *> **records) {
            return LCManagedSystemFind(selector, includeData, records);
        };
        managedKeychainMigration.systemRemove = ^OSStatus(NSString *itemClass, NSData *reference) {
            return LCManagedSystemRemove(itemClass, reference);
        };
    }

    // Only redirect imports from the guest bundle, not LC or OS frameworks.
    uint32_t before = gRebindCount;
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecItemAdd, LCManagedAdd, LCManagedKeychainGuestImage);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecItemCopyMatching, LCManagedCopy, LCManagedKeychainGuestImage);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecItemUpdate, LCManagedUpdate, LCManagedKeychainGuestImage);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecItemDelete, LCManagedDelete, LCManagedKeychainGuestImage);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecKeyCreateRandomKey, LCManagedRandomKey, LCManagedKeychainGuestImage);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecKeyCreateWithData, LCManagedCreateKeyWithData, LCManagedKeychainGuestImage);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecKeyGeneratePair, LCManagedKeyPair, LCManagedKeychainGuestImage);
#pragma clang diagnostic pop
    if (gRebindCount - before != 7) {
        LCKeychainLogMessage(@"init", @"none", errSecNotAvailable, @"hook-registration-failed");
        return NO;
    }
    return YES;
}

OSStatus new_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    NSMutableDictionary *attributesCopy = ((__bridge NSDictionary *)attributes).mutableCopy;
    attributesCopy[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    // for keychain deletion in LCUI
    attributesCopy[@"alis"] = containerId;
    
    OSStatus status = orig_SecItemAdd((__bridge CFDictionaryRef)attributesCopy, result);
    if(status == errSecParam) {
        return orig_SecItemAdd(attributes, result);
    }

    return status;
}

OSStatus new_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    NSMutableDictionary *queryCopy = ((__bridge NSDictionary *)query).mutableCopy;
    queryCopy[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    OSStatus status = orig_SecItemCopyMatching((__bridge CFDictionaryRef)queryCopy, result);
    if(status == errSecParam) {
        // if this search don't support kSecAttrAccessGroup, we just use the original search
        return orig_SecItemCopyMatching(query, result);
    }

    return status;
}

OSStatus new_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    NSMutableDictionary *queryCopy = ((__bridge NSDictionary *)query).mutableCopy;
    queryCopy[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    
    NSMutableDictionary *attrCopy = ((__bridge NSDictionary *)attributesToUpdate).mutableCopy;
    attrCopy[(__bridge id)kSecAttrAccessGroup] = accessGroup;

    OSStatus status = orig_SecItemUpdate((__bridge CFDictionaryRef)queryCopy, (__bridge CFDictionaryRef)attrCopy);

    if(status == errSecParam) {
        return orig_SecItemUpdate(query, attributesToUpdate);
    }

    return status;
}

OSStatus new_SecItemDelete(CFDictionaryRef query){
    NSMutableDictionary *queryCopy = ((__bridge NSDictionary *)query).mutableCopy;
    queryCopy[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    OSStatus status = orig_SecItemDelete((__bridge CFDictionaryRef)queryCopy);
    if(status == errSecParam) {
        return orig_SecItemDelete(query);
    }

    return status;
}

SecKeyRef new_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) {
    NSMutableDictionary *paramsCopy = ((__bridge NSDictionary *)parameters).mutableCopy;
    paramsCopy[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    SecKeyRef key = orig_SecKeyCreateRandomKey((__bridge CFDictionaryRef)paramsCopy, error);
    if(!key && error && *error) {
        CFRelease(*error);
        *error = NULL;
        key = orig_SecKeyCreateRandomKey(parameters, error);
    }
    
    return key;
}

SecKeyRef new_SecKeyCreateWithData(CFDataRef keyData, CFDictionaryRef parameters, CFErrorRef *error) {
    NSMutableDictionary *paramsCopy = ((__bridge NSDictionary *)parameters).mutableCopy;
    paramsCopy[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    SecKeyRef key = orig_SecKeyCreateWithData(keyData, (__bridge CFDictionaryRef)paramsCopy, error);
    if(!key && error && *error) {
        CFRelease(*error);
        *error = NULL;
        key = orig_SecKeyCreateWithData(keyData, parameters, error);
    }
    
    return key;
}

OSStatus new_SecKeyGeneratePair(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey) {
    NSMutableDictionary *queryCopy = ((__bridge NSDictionary *)parameters).mutableCopy;
    queryCopy[(__bridge id)kSecAttrAccessGroup] = accessGroup;
    OSStatus status = orig_SecKeyGeneratePair((__bridge CFDictionaryRef)queryCopy, publicKey, privateKey);
    if(status == errSecParam) {
        return orig_SecKeyGeneratePair(parameters, publicKey, privateKey);
    }
    
    return status;
}

void SecItemGuestHooksInit(void)  {

    containerId = [NSString stringWithUTF8String:getenv("HOME")].lastPathComponent;
    NSDictionary* infoDict = [NSUserDefaults guestContainerInfo];
    int keychainGroupId = [infoDict[@"keychainGroupId"] intValue];
    NSString* groupId = [LCSharedUtils teamIdentifier];
    if(keychainGroupId == 0) {
        accessGroup = [NSString stringWithFormat:@"%@.com.kdt.livecontainer.shared", groupId];
    } else {
        accessGroup = [NSString stringWithFormat:@"%@.com.kdt.livecontainer.shared.%d", groupId, keychainGroupId];
    }
    
    // check if the keychain access group is available
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: @"NonExistentKey",
        (__bridge id)kSecAttrService: @"NonExistentService",
        (__bridge id)kSecAttrAccessGroup: accessGroup,
        (__bridge id)kSecReturnData: @NO
    };
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
    if(status == errSecMissingEntitlement) {
        NSLog(@"[LC] failed to access keychain access group %@", accessGroup);
        return;
    }
    
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecItemAdd, new_SecItemAdd, nil);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecItemCopyMatching, new_SecItemCopyMatching, nil);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecItemUpdate, new_SecItemUpdate, nil);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecItemDelete, new_SecItemDelete, nil);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecKeyCreateRandomKey, new_SecKeyCreateRandomKey, nil);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecKeyCreateWithData, new_SecKeyCreateWithData, nil);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, SecKeyGeneratePair, new_SecKeyGeneratePair, nil);
}
