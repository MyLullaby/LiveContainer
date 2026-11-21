#import "LCManagedKeychain.h"
#import "LCDebugLog.h"
#import <objc/runtime.h>
@import LocalAuthentication;
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define KC(key) ((__bridge NSString *)key)
static NSString *const LCKeychainRecordRef = @"lc-ref";
static const NSUInteger LCKeychainMaxBytes = 8 * 1024 * 1024;
static char LCKeychainOwnedSoftwareKeyMarker;

@implementation LCKeychainMigration
@end

static NSArray *LCKeychainKeyUsageAttributes(void) {
    static NSArray *attributes;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        attributes = @[KC(kSecAttrCanEncrypt), KC(kSecAttrCanDecrypt), KC(kSecAttrCanDerive), KC(kSecAttrCanSign),
            KC(kSecAttrCanVerify), KC(kSecAttrCanWrap), KC(kSecAttrCanUnwrap)];
    });
    return attributes;
}

static NSDictionary *LCKeychainAttributeTypes(NSString *itemClass) {
    static NSDictionary *generic, *internet, *keys, *certificates, *identities;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSDictionary *common = @{
            KC(kSecAttrAccount): NSString.class, KC(kSecAttrAccessGroup): NSString.class,
            KC(kSecAttrLabel): NSString.class, KC(kSecAttrDescription): NSString.class,
            KC(kSecAttrComment): NSString.class, KC(kSecAttrCreator): NSNumber.class,
            KC(kSecAttrType): NSNumber.class, KC(kSecAttrIsInvisible): NSNumber.class,
            KC(kSecAttrIsNegative): NSNumber.class, KC(kSecAttrAccessible): NSString.class,
            KC(kSecAttrSynchronizable): NSObject.class,
        };
        NSMutableDictionary *attributes = common.mutableCopy;
        [attributes addEntriesFromDictionary:@{KC(kSecAttrService): NSString.class, KC(kSecAttrGeneric): NSData.class}];
        generic = attributes.copy;
        attributes = common.mutableCopy;
        for (NSString *key in @[KC(kSecAttrServer), KC(kSecAttrSecurityDomain), KC(kSecAttrPath),
                                KC(kSecAttrProtocol), KC(kSecAttrAuthenticationType)]) attributes[key] = NSString.class;
        attributes[KC(kSecAttrPort)] = NSNumber.class;
        internet = attributes.copy;
        attributes = [@{KC(kSecAttrKeyType): NSString.class, KC(kSecAttrKeyClass): NSString.class,
            KC(kSecAttrLabel): NSString.class, KC(kSecAttrApplicationTag): NSData.class,
            KC(kSecAttrApplicationLabel): NSData.class, KC(kSecAttrKeySizeInBits): NSNumber.class,
            KC(kSecAttrEffectiveKeySize): NSNumber.class, KC(kSecAttrIsPermanent): NSNumber.class,
            KC(kSecAttrAccessGroup): NSString.class, KC(kSecAttrAccessible): NSString.class,
            KC(kSecAttrSynchronizable): NSObject.class} mutableCopy];
        for (NSString *key in LCKeychainKeyUsageAttributes()) attributes[key] = NSNumber.class;
        keys = attributes.copy;
        certificates = @{KC(kSecAttrLabel): NSString.class, KC(kSecAttrAccessGroup): NSString.class,
            KC(kSecAttrAccessible): NSString.class, KC(kSecAttrSynchronizable): NSObject.class,
            KC(kSecAttrSubject): NSData.class, KC(kSecAttrIssuer): NSData.class,
            KC(kSecAttrSerialNumber): NSData.class, KC(kSecAttrPublicKeyHash): NSData.class,
            KC(kSecAttrCertificateEncoding): NSNumber.class};
        attributes = keys.mutableCopy;
        [attributes addEntriesFromDictionary:certificates];
        identities = attributes.copy;
    });
    if ([itemClass isEqualToString:KC(kSecClassGenericPassword)]) return generic;
    if ([itemClass isEqualToString:KC(kSecClassInternetPassword)]) return internet;
    if ([itemClass isEqualToString:KC(kSecClassKey)]) return keys;
    if ([itemClass isEqualToString:KC(kSecClassCertificate)]) return certificates;
    if ([itemClass isEqualToString:KC(kSecClassIdentity)]) return identities;
    return nil;
}

static BOOL LCKeychainIsBoolean(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID();
}

static id LCKeychainByteAttribute(id value) {
    return [value isKindOfClass:NSString.class] ? [value dataUsingEncoding:NSUTF8StringEncoding] : value;
}

static OSStatus LCKeyCreationErrorStatus(CFErrorRef error) {
    return error && CFEqual(CFErrorGetDomain(error), kCFErrorDomainOSStatus) ?
        (OSStatus)CFErrorGetCode(error) : errSecInternalComponent;
}

static NSDictionary<NSString *, NSNumber *> *LCKeychainAccessibilityBuckets(void) {
    static NSDictionary<NSString *, NSNumber *> *buckets;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        // Keep the legacy values for exact matching; store them under their first-unlock replacements.
        buckets = @{
            KC(kSecAttrAccessibleWhenUnlocked): @NO,
            KC(kSecAttrAccessibleWhenUnlockedThisDeviceOnly): @NO,
            KC(kSecAttrAccessibleAfterFirstUnlock): @YES,
            KC(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly): @YES,
            KC(kSecAttrAccessibleAlways): @YES,
            KC(kSecAttrAccessibleAlwaysThisDeviceOnly): @YES,
        };
#pragma clang diagnostic pop
    });
    return buckets;
}

static BOOL LCKeychainValidAttribute(NSString *key, id value, NSDictionary *types, BOOL query) {
    Class expected = types[key];
    // Some guests pass accounts as opaque bytes. Do not normalize them to text.
    if (expected && [key isEqual:KC(kSecAttrAccount)] && [value isKindOfClass:NSData.class]) return YES;
    if (!expected || ![value isKindOfClass:expected]) return NO;
    if ([key isEqualToString:KC(kSecAttrSynchronizable)]) {
        return LCKeychainIsBoolean(value) || (query && [value isEqual:KC(kSecAttrSynchronizableAny)]);
    }
    if ([key isEqualToString:KC(kSecAttrAccessible)]) {
        return LCKeychainAccessibilityBuckets()[value] != nil;
    }
    if ([key isEqualToString:KC(kSecAttrIsInvisible)] || [key isEqualToString:KC(kSecAttrIsNegative)]) {
        return LCKeychainIsBoolean(value);
    }
    if ([key isEqual:KC(kSecAttrIsPermanent)] || (expected == NSNumber.class && [LCKeychainKeyUsageAttributes() containsObject:key])) {
        return LCKeychainIsBoolean(value);
    }
    if ([key isEqual:KC(kSecAttrKeySizeInBits)] || [key isEqual:KC(kSecAttrEffectiveKeySize)]) {
        return !LCKeychainIsBoolean(value) && [value longLongValue] > 0 && [value isEqual:@([value longLongValue])];
    }
    if ([key isEqualToString:KC(kSecAttrPort)]) {
        NSInteger port = [value integerValue];
        return !LCKeychainIsBoolean(value) && port >= 0 && port <= 65535 && [value isEqual:@(port)];
    }
    return YES;
}

static OSStatus LCKeychainNormalizeACL(NSDictionary *__strong *input, BOOL passwordRead, NSString **reason) {
    if ([(*input)[KC(kSecAttrAccessible)] isEqual:KC(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)]) {
        *reason = @"passcode-bound-accessibility-not-supported";
        return errSecUnimplemented;
    }
    id control = (*input)[KC(kSecAttrAccessControl)];
    if (!control) return errSecSuccess;
    CFTypeRef reference = (__bridge CFTypeRef)control;
    if (CFGetTypeID(reference) != SecAccessControlGetTypeID()) {
        *reason = @"invalid-access-control-type";
        return errSecParam;
    }
    if (passwordRead) {
        // ACL metadata in a read does not select records or replace their stored protection.
        NSMutableDictionary *normalized = [*input mutableCopy];
        [normalized removeObjectForKey:KC(kSecAttrAccessControl)];
        *input = normalized.copy;
        return errSecSuccess;
    }
    for (NSString *protection in LCKeychainAccessibilityBuckets()) {
        // Only an exact match to a no-flags ACL can use the store's accessibility policy.
        SecAccessControlRef ordinary = SecAccessControlCreateWithFlags(NULL, (__bridge CFTypeRef)protection, 0, NULL);
        BOOL matches = ordinary && CFEqual(reference, ordinary);
        if (ordinary) CFRelease(ordinary);
        if (!matches) continue;
        id accessible = (*input)[KC(kSecAttrAccessible)];
        if (accessible && ![accessible isEqual:protection]) {
            *reason = @"conflicting-access-control";
            return errSecParam;
        }
        NSMutableDictionary *normalized = [*input mutableCopy];
        [normalized removeObjectForKey:KC(kSecAttrAccessControl)];
        normalized[KC(kSecAttrAccessible)] = protection;
        *input = normalized.copy;
        return errSecSuccess;
    }
    *reason = @"access-control-policy-not-supported";
    return errSecUnimplemented;
}

static NSString *LCKeychainOptionValueType(id value) {
    if ([value isKindOfClass:NSString.class]) return @"string";
    if (LCKeychainIsBoolean(value)) return @"boolean";
    if ([value isKindOfClass:NSNumber.class]) return @"number";
    if ([value isKindOfClass:NSData.class]) return @"data";
    if ([value isKindOfClass:NSDate.class]) return @"date";
    if ([value isKindOfClass:NSArray.class]) return @"array";
    if ([value isKindOfClass:NSDictionary.class]) return @"dictionary";
    if (value == NSNull.null) return @"null";
    return @"other";
}

static NSString *LCKeychainSafeOption(id key, id value, NSDictionary *types) {
    // Never echo arbitrary dictionary keys or attribute values into diagnostics.
    static NSArray<NSString *> *known;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        known = @[KC(kSecAttrAccessControl), KC(kSecAttrAccessible), KC(kSecAttrSynchronizable),
                  KC(kSecReturnRef), KC(kSecReturnPersistentRef), KC(kSecValueRef), KC(kSecValuePersistentRef),
                  KC(kSecUseAuthenticationContext), KC(kSecUseOperationPrompt), KC(kSecUseAuthenticationUI),
                  KC(kSecUseNoAuthenticationUI), KC(kSecUseDataProtectionKeychain),
                  KC(kSecMatchItemList), KC(kSecUseItemList), KC(kSecMatchLimit),
                  KC(kSecReturnData), KC(kSecReturnAttributes), KC(kSecValueData),
                  KC(kSecAttrTokenID), KC(kSecAttrCreationDate), KC(kSecAttrModificationDate),
                  KC(kSecMatchPolicy), KC(kSecMatchIssuers), KC(kSecMatchEmailAddressIfPresent),
                  KC(kSecMatchSubjectContains), KC(kSecMatchCaseInsensitive), KC(kSecMatchTrustedOnly),
                  KC(kSecMatchValidOnDate)];
#pragma clang diagnostic pop
    });
    NSString *name = nil;
    if ([key isKindOfClass:NSString.class]) {
        NSUInteger index = [known indexOfObject:key];
        if (index != NSNotFound) name = known[index];
        else for (NSString *attribute in types) {
            if ([attribute isEqual:key]) { name = attribute; break; }
        }
    }
    NSString *valueType = LCKeychainOptionValueType(value);
    return name ? [NSString stringWithFormat:@"unsupported-option:%@ value-type=%@", name, valueType] :
        [NSString stringWithFormat:@"unsupported-or-invalid-option field=unknown value-type=%@", valueType];
}

static BOOL LCKeychainSoftwareKey(NSDictionary *attributes) {
    id type = attributes[KC(kSecAttrKeyType)], keyClass = attributes[KC(kSecAttrKeyClass)];
    return ([type isEqual:KC(kSecAttrKeyTypeRSA)] || [type isEqual:KC(kSecAttrKeyTypeECSECPrimeRandom)]) &&
        ([keyClass isEqual:KC(kSecAttrKeyClassPrivate)] || [keyClass isEqual:KC(kSecAttrKeyClassPublic)]);
}

static SecKeyRef LCKeychainRestoreKey(NSDictionary *item) CF_RETURNS_RETAINED {
    if (!LCKeychainSoftwareKey(item)) return NULL;
    NSDictionary *parameters = @{KC(kSecAttrKeyType): item[KC(kSecAttrKeyType)],
        KC(kSecAttrKeyClass): item[KC(kSecAttrKeyClass)], KC(kSecAttrIsPermanent): @NO};
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)item[KC(kSecValueData)], (__bridge CFDictionaryRef)parameters, NULL);
    if (key) objc_setAssociatedObject((__bridge id)key, &LCKeychainOwnedSoftwareKeyMarker, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return key;
}

static OSStatus LCKeychainPrepareKey(NSMutableDictionary *record, id reference, BOOL identityImport, NSString **reason) {
    if (reference && CFGetTypeID((__bridge CFTypeRef)reference) != SecKeyGetTypeID()) {
        *reason = @"invalid-key-reference";
        return errSecParam;
    }
    SecKeyRef key = reference ? (__bridge SecKeyRef)reference : LCKeychainRestoreKey(record);
    if (!key) {
        *reason = @"invalid-software-key-data";
        return errSecParam;
    }
    NSDictionary *actual = CFBridgingRelease(SecKeyCopyAttributes(key));
    NSData *data = nil;
    // Memory-only software keys can still report themselves as permanent.
    NSString *rejection = nil;
    if (!actual) rejection = @"key-attributes-unavailable";
    else if (actual[KC(kSecAttrTokenID)]) rejection = @"key-token-backed";
    else if (actual[KC(kSecAttrAccessControl)]) rejection = @"key-access-controlled";
    else if ([actual[KC(kSecAttrIsExtractable)] isEqual:@NO]) rejection = @"key-not-extractable";
    else if (!LCKeychainSoftwareKey(actual)) rejection = @"unsupported-key-type-or-class";
    else if (reference && !identityImport && [actual[KC(kSecAttrIsPermanent)] boolValue] &&
             !objc_getAssociatedObject(reference, &LCKeychainOwnedSoftwareKeyMarker)) rejection = @"untracked-permanent-key-reference";
    else {
        data = CFBridgingRelease(SecKeyCopyExternalRepresentation(key, NULL));
        if (!data.length) rejection = @"key-export-failed";
    }
    if (!reference) CFRelease(key);
    if (rejection) {
        *reason = rejection;
        return errSecUnimplemented;
    }

    // Only persist policies that the reconstructed software key actually enforces.
    NSArray *intrinsic = [@[KC(kSecAttrKeyType), KC(kSecAttrKeyClass), KC(kSecAttrApplicationLabel),
        KC(kSecAttrKeySizeInBits), KC(kSecAttrEffectiveKeySize)] arrayByAddingObjectsFromArray:LCKeychainKeyUsageAttributes()];
    record[KC(kSecValueData)] = data;
    if (reference) {
        SecKeyRef restored = LCKeychainRestoreKey(@{KC(kSecValueData): data,
            KC(kSecAttrKeyType): actual[KC(kSecAttrKeyType)], KC(kSecAttrKeyClass): actual[KC(kSecAttrKeyClass)]});
        if (!restored) {
            *reason = @"key-restore-failed";
            return errSecDecode;
        }
        NSDictionary *restoredAttributes = CFBridgingRelease(SecKeyCopyAttributes(restored));
        CFRelease(restored);
        actual = restoredAttributes;
    }
    for (NSString *name in intrinsic) {
        if (record[name] && ![record[name] isEqual:actual[name]]) {
            *reason = [@"key-attribute-mismatch:" stringByAppendingString:name];
            return errSecUnimplemented;
        }
        if (actual[name]) record[name] = actual[name];
    }
    if (![record[KC(kSecAttrApplicationLabel)] isKindOfClass:NSData.class]) {
        *reason = @"key-application-label-unavailable";
        return errSecUnimplemented;
    }
    record[KC(kSecAttrIsPermanent)] = @YES;
    return errSecSuccess;
}

static OSStatus LCKeychainPrepareCertificate(NSMutableDictionary *record, id reference) {
    if (reference && CFGetTypeID((__bridge CFTypeRef)reference) != SecCertificateGetTypeID()) return errSecParam;
    NSData *input = record[KC(kSecValueData)];
    if (!reference && !input.length) return errSecParam;
    SecCertificateRef cert = reference ? (__bridge SecCertificateRef)reference :
        SecCertificateCreateWithData(NULL, (__bridge CFDataRef)input);
    if (!cert) return errSecDecode;
    NSData *der = CFBridgingRelease(SecCertificateCopyData(cert));
    NSData *subject = CFBridgingRelease(SecCertificateCopyNormalizedSubjectSequence(cert));
    NSData *issuer = CFBridgingRelease(SecCertificateCopyNormalizedIssuerSequence(cert));
    NSData *serial = CFBridgingRelease(SecCertificateCopySerialNumberData(cert, NULL));
    SecKeyRef key = SecCertificateCopyKey(cert);
    NSDictionary *keyAttributes = key ? CFBridgingRelease(SecKeyCopyAttributes(key)) : nil;
    if (key) CFRelease(key);
    NSString *label = CFBridgingRelease(SecCertificateCopySubjectSummary(cert));
    if (!reference) CFRelease(cert);
    if (!der.length || !subject || !issuer || !serial.length) return errSecDecode;
    NSMutableDictionary *intrinsic = [@{KC(kSecAttrSubject): subject, KC(kSecAttrIssuer): issuer,
        KC(kSecAttrSerialNumber): serial, KC(kSecAttrCertificateEncoding): @3} mutableCopy];
    NSData *keyHash = keyAttributes[KC(kSecAttrApplicationLabel)];
    if ([keyHash isKindOfClass:NSData.class] && keyHash.length) intrinsic[KC(kSecAttrPublicKeyHash)] = keyHash;
    for (NSString *name in LCKeychainAttributeTypes(KC(kSecClassCertificate))) {
        if ([name isEqual:KC(kSecAttrLabel)] || [name isEqual:KC(kSecAttrAccessGroup)] ||
            [name isEqual:KC(kSecAttrAccessible)] || [name isEqual:KC(kSecAttrSynchronizable)]) continue;
        if (record[name] && ![record[name] isEqual:intrinsic[name]]) return errSecParam;
    }
    [record addEntriesFromDictionary:intrinsic];
    if (!record[KC(kSecAttrLabel)] && label) record[KC(kSecAttrLabel)] = label;
    record[KC(kSecValueData)] = der;
    return errSecSuccess;
}

static NSArray *LCKeychainIdentity(NSDictionary *item) {
    // Retain the sync flag for local identity and matching, never for routing to iCloud.
    NSArray *common = @[item[KC(kSecClass)], item[KC(kSecAttrAccessGroup)] ?: @"", item[KC(kSecAttrSynchronizable)] ?: @NO];
    if ([item[KC(kSecClass)] isEqual:KC(kSecClassKey)]) {
        return [common arrayByAddingObjectsFromArray:@[item[KC(kSecAttrKeyClass)], item[KC(kSecAttrKeyType)],
            item[KC(kSecAttrApplicationLabel)], item[KC(kSecAttrApplicationTag)] ?: NSData.data]];
    }
    if ([item[KC(kSecClass)] isEqual:KC(kSecClassCertificate)]) {
        return [common arrayByAddingObjectsFromArray:@[item[KC(kSecAttrIssuer)], item[KC(kSecAttrSerialNumber)]]];
    }
    common = [common arrayByAddingObject:item[KC(kSecAttrAccount)] ?: @""];
    if ([item[KC(kSecClass)] isEqual:KC(kSecClassGenericPassword)]) {
        return [common arrayByAddingObject:item[KC(kSecAttrService)] ?: @""];
    }
    return [common arrayByAddingObjectsFromArray:@[
        item[KC(kSecAttrServer)] ?: @"", item[KC(kSecAttrSecurityDomain)] ?: @"",
        item[KC(kSecAttrProtocol)] ?: @"", item[KC(kSecAttrAuthenticationType)] ?: KC(kSecAttrAuthenticationTypeDefault),
        item[KC(kSecAttrPort)] ?: @0, item[KC(kSecAttrPath)] ?: @"",
    ]];
}

static OSStatus LCKeychainValidateStore(NSArray *items, NSIndexSet *updated, NSString **reason) {
    enum { UntouchedRecord = 1, UpdatedRecord = 2 };
    if (![items isKindOfClass:NSArray.class]) return errSecDecode;
    NSMutableDictionary<NSArray *, NSNumber *> *identities = [NSMutableDictionary dictionary];
    BOOL conflictsWithExisting = NO, conflictsWithinUpdate = NO;
    for (NSUInteger index = 0; index < items.count; index++) {
        NSDictionary *item = items[index];
        if (![item isKindOfClass:NSDictionary.class]) return errSecDecode;
        NSString *itemClass = item[KC(kSecClass)];
        NSDictionary *types = [itemClass isKindOfClass:NSString.class] ? LCKeychainAttributeTypes(itemClass) : nil;
        if (!types || [itemClass isEqual:KC(kSecClassIdentity)] || ![item[KC(kSecValueData)] isKindOfClass:NSData.class] ||
            ![item[KC(kSecAttrCreationDate)] isKindOfClass:NSDate.class] ||
            ![item[KC(kSecAttrModificationDate)] isKindOfClass:NSDate.class] || !item[KC(kSecAttrAccessible)]) return errSecDecode;
        for (NSString *key in item) {
            if ([key isEqual:KC(kSecClass)] || [key isEqual:KC(kSecValueData)] ||
                [key isEqual:KC(kSecAttrCreationDate)] || [key isEqual:KC(kSecAttrModificationDate)]) continue;
            if ([key isEqual:LCKeychainRecordRef] && [item[key] isKindOfClass:NSData.class]) continue;
            if (!LCKeychainValidAttribute(key, item[key], types, NO)) return errSecDecode;
        }
        if ([itemClass isEqual:KC(kSecClassKey)] && (!LCKeychainSoftwareKey(item) ||
            ![item[KC(kSecAttrApplicationLabel)] length] || ![item[KC(kSecAttrIsPermanent)] boolValue] ||
            ![item[KC(kSecValueData)] length])) return errSecDecode;
        if ([itemClass isEqual:KC(kSecClassCertificate)] && (!item[KC(kSecAttrIssuer)] ||
            ![item[KC(kSecAttrSerialNumber)] length] || ![item[KC(kSecValueData)] length])) return errSecDecode;
        NSArray *identity = LCKeychainIdentity(item);
        // A destination identity can be shared by updated records, untouched records, or both.
        NSUInteger current = [updated containsIndex:index] ? UpdatedRecord : UntouchedRecord;
        NSUInteger previous = [identities[identity] unsignedIntegerValue];
        if (previous) {
            if (!updated) return errSecDuplicateItem;
            conflictsWithExisting |= (previous | current) == (UntouchedRecord | UpdatedRecord);
            conflictsWithinUpdate |= current == UpdatedRecord && (previous & UpdatedRecord) != 0;
        }
        identities[identity] = @(previous | current);
    }
    if (!conflictsWithExisting && !conflictsWithinUpdate) return errSecSuccess;
    *reason = conflictsWithExisting && conflictsWithinUpdate ? @"duplicate-item-update-both" :
        conflictsWithExisting ? @"duplicate-item-update-existing" : @"duplicate-item-update-batch";
    return errSecDuplicateItem;
}

static NSDictionary *LCKeychainPasswordDefaults(NSString *itemClass) {
    static NSDictionary *generic, *internet;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSDictionary *common = @{KC(kSecAttrAccount): @"", KC(kSecAttrSynchronizable): @NO};
        NSMutableDictionary *values = common.mutableCopy;
        values[KC(kSecAttrService)] = @"";
        generic = values.copy;
        values = common.mutableCopy;
        [values addEntriesFromDictionary:@{KC(kSecAttrServer): @"", KC(kSecAttrSecurityDomain): @"",
            KC(kSecAttrPath): @"", KC(kSecAttrProtocol): @"", KC(kSecAttrPort): @0,
            KC(kSecAttrAuthenticationType): KC(kSecAttrAuthenticationTypeDefault)}];
        internet = values.copy;
    });
    return [itemClass isEqual:KC(kSecClassGenericPassword)] ? generic : internet;
}

static NSData *LCKeychainNewRef(NSString *itemClass) {
    unsigned char bytes[24] = "LCKC";
    memcpy(bytes + 4, itemClass.UTF8String, 4);
    [NSUUID.UUID getUUIDBytes:bytes + 8];
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

static NSString *LCKeychainRefClass(id reference) {
    if (![reference isKindOfClass:NSData.class] || [reference length] != 24) return nil;
    const unsigned char *bytes = [reference bytes];
    if (memcmp(bytes, "LCKC", 4)) return nil;
    return [[NSString alloc] initWithBytes:bytes + 4 length:4 encoding:NSASCIIStringEncoding];
}

static NSData *LCKeychainRefWithClass(NSData *reference, NSString *itemClass) {
    if (reference.length != 24) return nil;
    NSMutableData *result = reference.mutableCopy;
    [result replaceBytesInRange:NSMakeRange(4, 4) withBytes:itemClass.UTF8String];
    return result.copy;
}

static id LCKeychainResult(NSDictionary *item, NSDictionary *privateKey, NSDictionary *defaults,
                           BOOL returnData, BOOL returnAttributes, BOOL returnRef, BOOL returnPersistentRef) {
    id reference = nil;
    if (returnRef) {
        if ([item[KC(kSecClass)] isEqual:KC(kSecClassKey)]) {
            reference = CFBridgingRelease(LCKeychainRestoreKey(item));
        } else {
            SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)item[KC(kSecValueData)]);
            if (!cert) return nil;
            if (privateKey) {
                SecKeyRef publicKey = SecCertificateCopyKey(cert);
                SecKeyRef key = LCKeychainRestoreKey(privateKey);
                if (publicKey && key) {
                    reference = CFBridgingRelease(SecIdentityCreate(NULL, cert, key));
                }
                if (publicKey) CFRelease(publicKey);
                if (key) CFRelease(key);
                CFRelease(cert);
            } else {
                reference = CFBridgingRelease(cert);
            }
        }
    }
    if (returnRef && !reference) return nil;
    NSData *persistentRef = returnPersistentRef ? item[LCKeychainRecordRef] : nil;
    if (persistentRef && privateKey) persistentRef = LCKeychainRefWithClass(persistentRef, KC(kSecClassIdentity));
    if (returnPersistentRef && !persistentRef) return nil;
    if (!returnAttributes && returnRef + returnData + returnPersistentRef <= 1) {
        return reference ?: (returnData ? item[KC(kSecValueData)] : persistentRef);
    }
    NSMutableDictionary *result = returnAttributes ? defaults.mutableCopy : [NSMutableDictionary dictionary];
    if (returnAttributes && privateKey) [result addEntriesFromDictionary:privateKey];
    if (returnAttributes) [result addEntriesFromDictionary:item];
    if (returnAttributes && privateKey) {
        result[KC(kSecClass)] = KC(kSecClassIdentity);
        result[KC(kSecAttrSynchronizable)] = privateKey[KC(kSecAttrSynchronizable)] ?: @NO;
    }
    if (returnData) result[KC(kSecValueData)] = item[KC(kSecValueData)];
    [result removeObjectForKey:LCKeychainRecordRef];
    if (returnRef) result[KC(kSecValueRef)] = reference;
    if (returnPersistentRef) result[KC(kSecValuePersistentRef)] = persistentRef;
    if (!returnData) [result removeObjectForKey:KC(kSecValueData)];
    return result.copy;
}

static NSArray *LCKeychainIdentityPair(NSDictionary *item, NSString *hashAttribute) {
    NSData *hash = item[hashAttribute];
    return hash.length ? @[item[KC(kSecAttrAccessGroup)] ?: @"", hash] : nil;
}

static BOOL LCKeychainMatches(NSDictionary *item, NSDictionary *key, NSDictionary *query, NSDictionary *defaults) {
    for (NSString *attribute in query) {
        if (key && [attribute isEqual:KC(kSecClass)]) continue;
        id value = key && [attribute isEqual:KC(kSecAttrSynchronizable)] ? key[attribute] : item[attribute] ?: key[attribute];
        if (![query[attribute] isEqual:(value ?: defaults[attribute])]) return NO;
    }
    return YES;
}

static BOOL LCKeychainCertificateMatches(NSData *data, NSString *email, NSDate *date, NSString *subject,
                                          BOOL ignoreCase, SecPolicyRef policy, BOOL trustedOnly) {
    SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
    if (!certificate) return NO;
    BOOL matches = YES;
    if (email) {
        CFArrayRef addresses = NULL;
        OSStatus status = SecCertificateCopyEmailAddresses(certificate, &addresses);
        NSArray<NSString *> *emails = CFBridgingRelease(addresses);
        matches = NO;
        if (status == errSecSuccess) {
            for (NSString *address in emails) {
                if ([address caseInsensitiveCompare:email] == NSOrderedSame) { matches = YES; break; }
            }
        }
    }
    if (matches && date) {
        if (@available(iOS 18.0, macOS 15.0, *)) {
            NSDate *start = CFBridgingRelease(SecCertificateCopyNotValidBeforeDate(certificate));
            NSDate *end = CFBridgingRelease(SecCertificateCopyNotValidAfterDate(certificate));
            matches = start && end && [start compare:date] != NSOrderedDescending && [end compare:date] != NSOrderedAscending;
        } else {
            matches = NO;
        }
    }
    if (matches && subject) {
        NSString *summary = CFBridgingRelease(SecCertificateCopySubjectSummary(certificate));
        matches = summary && [summary rangeOfString:subject options:ignoreCase ? NSCaseInsensitiveSearch : 0].location != NSNotFound;
    }
    if (matches && (policy || trustedOnly)) {
        // Use system trust, but do not fetch certificates over the network while the LC store is locked.
        SecPolicyRef basic = trustedOnly ? SecPolicyCreateBasicX509() : NULL;
        SecPolicyRef policies[] = {policy ?: basic, policy ? basic : NULL};
        for (NSUInteger i = 0; matches && i < 2 && policies[i]; i++) {
            SecTrustRef trust = NULL;
            matches = SecTrustCreateWithCertificates(certificate, policies[i], &trust) == errSecSuccess &&
                SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess &&
                (!(policy && i == 0 && date) || SecTrustSetVerifyDate(trust, (__bridge CFDateRef)date) == errSecSuccess) &&
                SecTrustEvaluateWithError(trust, NULL);
            if (trust) CFRelease(trust);
        }
        if (trustedOnly && !basic) matches = NO;
        if (basic) CFRelease(basic);
    }
    CFRelease(certificate);
    return matches;
}

static BOOL LCKeychainAfterFirstUnlock(NSDictionary *item) {
    return [LCKeychainAccessibilityBuckets()[item[KC(kSecAttrAccessible)]] boolValue];
}

static NSData *LCKeychainReadStore(NSURL *file, OSStatus *status, NSString **reason, BOOL *denied) {
    int fd = open(file.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (denied) *denied = errno == EACCES || errno == EPERM;
        if (errno != ENOENT) { *status = errSecNotAvailable; *reason = @"store-open"; }
        return nil;
    }
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size > (off_t)LCKeychainMaxBytes) {
        close(fd);
        *status = errSecDecode; *reason = @"store-invalid-file";
        return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)info.st_size];
    char *bytes = data.mutableBytes;
    NSUInteger offset = 0;
    while (offset < data.length) {
        ssize_t count = read(fd, bytes + offset, data.length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && denied) *denied = errno == EACCES || errno == EPERM;
        if (count <= 0) break;
        offset += (NSUInteger)count;
    }
    close(fd);
    if (offset == data.length) return data;
    *status = errSecNotAvailable; *reason = @"store-read";
    return nil;
}

static OSStatus LCKeychainWriteStore(NSURL *store, NSArray *items, NSArray *blocked, NSDictionary *migrationState,
                                     BOOL replace, NSString **reason) {
    NSMutableArray *unlocked = [NSMutableArray array], *afterFirstUnlock = [NSMutableArray array];
    for (NSDictionary *item in items) {
        NSDictionary *record = item;
        if (!record[LCKeychainRecordRef]) {
            NSMutableDictionary *withRef = item.mutableCopy;
            withRef[LCKeychainRecordRef] = LCKeychainNewRef(item[KC(kSecClass)]);
            record = withRef;
        }
        [(LCKeychainAfterFirstUnlock(item) ? afterFirstUnlock : unlocked) addObject:record];
    }
    NSArray *documents = @[@{@"items": unlocked, @"legacy-blocked": blocked,
        @"migration": migrationState ?: @{}}, afterFirstUnlock];
    NSMutableArray<NSData *> *encoded = [NSMutableArray arrayWithCapacity:2];
    NSUInteger total = 0;
    for (id document in documents) {
        NSData *data = [NSPropertyListSerialization dataWithPropertyList:document
            format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
        if (!data || data.length > LCKeychainMaxBytes - total) {
            *reason = @"store-size-or-encode";
            return errSecAllocate;
        }
        total += data.length;
        [encoded addObject:data];
    }

    NSURL *parent = store.URLByDeletingLastPathComponent;
    char *temporaryPath = strdup([parent URLByAppendingPathComponent:@"items-v2.XXXXXX"].fileSystemRepresentation);
    if (!temporaryPath || !mkdtemp(temporaryPath)) {
        free(temporaryPath);
        *reason = @"store-staging";
        return errSecNotAvailable;
    }
    NSURL *temporary = [NSURL fileURLWithFileSystemRepresentation:temporaryPath isDirectory:YES relativeToURL:nil];
    NSDataWritingOptions unlockedOptions = 0, afterFirstUnlockOptions = 0;
#if TARGET_OS_IPHONE
    afterFirstUnlockOptions = NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication;
    unlockedOptions = unlocked.count || blocked.count || migrationState[@"removals"] ?
        NSDataWritingFileProtectionComplete : afterFirstUnlockOptions;
#endif
    BOOL committed = [encoded[0] writeToURL:[temporary URLByAppendingPathComponent:@"unlocked.plist"]
                                   options:unlockedOptions error:nil] &&
        [encoded[1] writeToURL:[temporary URLByAppendingPathComponent:@"after-first-unlock.plist"]
                       options:afterFirstUnlockOptions error:nil] &&
        renameatx_np(AT_FDCWD, temporaryPath, AT_FDCWD, store.fileSystemRepresentation,
                     replace ? RENAME_SWAP : RENAME_EXCL) == 0;
    [NSFileManager.defaultManager removeItemAtURL:temporary error:nil];
    free(temporaryPath);
    if (committed) return errSecSuccess;
    *reason = @"store-write";
    return errSecNotAvailable;
}

@interface LCKeychainSnapshot : NSObject
@property(nonatomic, copy) NSArray *items;
@property(nonatomic, copy) NSArray *blocked;
@property(nonatomic, copy) NSDictionary *migration;
@property(nonatomic) BOOL split;
@property(nonatomic) BOOL v1;
@property(nonatomic) BOOL partial;
@end

@implementation LCKeychainSnapshot
@end

static LCKeychainSnapshot *LCKeychainLoadStore(NSURL *directory, BOOL allowPartial, BOOL allowEmptyDirectory,
                                               OSStatus *status, NSString **reason) {
    NSURL *v1 = [directory URLByAppendingPathComponent:@"items-v1.plist"];
    NSURL *store = [directory URLByAppendingPathComponent:@"items-v2" isDirectory:YES];
    NSURL *unlocked = [store URLByAppendingPathComponent:@"unlocked.plist"];
    struct stat info;
    BOOL split = lstat(store.fileSystemRepresentation, &info) == 0;
    if ((split && !S_ISDIR(info.st_mode)) || (!split && errno != ENOENT)) {
        *status = errSecNotAvailable; *reason = @"store-directory"; return nil;
    }
    BOOL denied = NO;
    NSData *data = LCKeychainReadStore(split ? unlocked : v1, status, reason, &denied);
    BOOL partial = split && denied && allowPartial;
    if (partial) *status = errSecSuccess;
    if (*status != errSecSuccess) return nil;
    if (split && !data && !partial) {
        NSArray *entries = allowEmptyDirectory ?
            [NSFileManager.defaultManager contentsOfDirectoryAtPath:store.path error:nil] : nil;
        if (!entries || entries.count) {
            *status = errSecDecode; *reason = @"store-missing-unlocked"; return nil;
        }
        // Only a proven empty old shell can fall back to the old v1 file.
        split = NO;
        data = LCKeychainReadStore(v1, status, reason, NULL);
        if (*status != errSecSuccess) return nil;
    }
    id decoded = data ? [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil] : @[];
    BOOL hasMetadata = [decoded isKindOfClass:NSDictionary.class];
    NSArray *items = hasMetadata ? decoded[@"items"] : decoded;
    NSArray *blocked = hasMetadata ? decoded[@"legacy-blocked"] : @[];
    NSDictionary *migrationState = hasMetadata ? decoded[@"migration"] ?: @{} : @{};
    if (LCKeychainValidateStore(items, nil, NULL) != errSecSuccess || ![blocked isKindOfClass:NSArray.class] ||
        ![migrationState isKindOfClass:NSDictionary.class]) {
        *status = errSecDecode; *reason = @"store-invalid-records"; return nil;
    }
    for (id entry in blocked) {
        if (![entry isKindOfClass:NSDictionary.class]) { *status = errSecDecode; break; }
        NSDictionary *filter = entry;
        id filterClass = filter[KC(kSecClass)];
        if (![filterClass isEqual:KC(kSecClassGenericPassword)] && ![filterClass isEqual:KC(kSecClassInternetPassword)]) {
            *status = errSecDecode; break;
        }
        NSDictionary *filterTypes = LCKeychainAttributeTypes(filterClass);
        for (NSString *key in filter) {
            if (![key isEqual:KC(kSecClass)] && !LCKeychainValidAttribute(key, filter[key], filterTypes, YES)) {
                *status = errSecDecode; break;
            }
        }
        if (*status != errSecSuccess) break;
    }
    if (*status != errSecSuccess) { *reason = @"store-invalid-legacy-filters"; return nil; }
    if (split) {
        NSData *afterData = LCKeychainReadStore([store URLByAppendingPathComponent:@"after-first-unlock.plist"], status, reason, NULL);
        if (*status != errSecSuccess) return nil;
        id afterItems = afterData ? [NSPropertyListSerialization propertyListWithData:afterData options:0 format:nil error:nil] : nil;
        if (![afterItems isKindOfClass:NSArray.class]) {
            *status = errSecDecode; *reason = @"store-invalid-after-first-unlock"; return nil;
        }
        items = [items arrayByAddingObjectsFromArray:afterItems];
        if (LCKeychainValidateStore(items, nil, NULL) != errSecSuccess) {
            *status = errSecDecode; *reason = @"store-invalid-records"; return nil;
        }
    }
    LCKeychainSnapshot *snapshot = [LCKeychainSnapshot new];
    snapshot.items = items;
    snapshot.blocked = blocked;
    snapshot.migration = migrationState;
    snapshot.split = split;
    snapshot.v1 = !split && data != nil;
    snapshot.partial = partial;
    return snapshot;
}

static NSArray *LCKeychainAssignReferences(NSArray *items) {
    NSMutableArray *referenced = [NSMutableArray arrayWithCapacity:items.count];
    // Readback is partitioned in this order, regardless of the input order.
    for (NSUInteger bucket = 0; bucket < 2; bucket++) {
        for (NSDictionary *item in items) {
            if (LCKeychainAfterFirstUnlock(item) != (BOOL)bucket) continue;
            if (item[LCKeychainRecordRef]) [referenced addObject:item];
            else {
                NSMutableDictionary *record = item.mutableCopy;
                record[LCKeychainRecordRef] = LCKeychainNewRef(record[KC(kSecClass)]);
                [referenced addObject:record];
            }
        }
    }
    return referenced;
}

static OSStatus LCKeychainSaveVerified(NSURL *directory, NSURL *store, NSArray *items, NSArray *blocked,
                                       NSDictionary *state, BOOL replace, NSString **reason) {
    OSStatus status = LCKeychainWriteStore(store, items, blocked, state, replace, reason);
    if (status != errSecSuccess) return status;
    LCKeychainSnapshot *saved = LCKeychainLoadStore(directory, NO, NO, &status, reason);
    if (!saved) return status;
    if (![saved.items isEqual:items] || ![saved.blocked isEqual:blocked] || ![saved.migration isEqual:state]) {
        *reason = @"migration-readback-mismatch";
        return errSecDecode;
    }
    return errSecSuccess;
}

static OSStatus LCKeychainRetireOldStore(NSURL *directory, NSURL *store, LCKeychainSnapshot *snapshot,
                                         NSURL *source, NSString **reason) {
    struct stat info;
    NSURL *parent = source.URLByDeletingLastPathComponent;
    BOOL hasParent = lstat(parent.fileSystemRepresentation, &info) == 0;
    if ((hasParent && !S_ISDIR(info.st_mode)) || (!hasParent && errno != ENOENT)) {
        *reason = @"old-store-parent"; return errSecNotAvailable;
    }
    int oldLock = -1;
    if (lstat(source.fileSystemRepresentation, &info) == 0) {
        if (S_ISDIR(info.st_mode)) oldLock = open([source URLByAppendingPathComponent:@"items.lock"].fileSystemRepresentation,
            O_CREAT | O_RDWR | O_EXLOCK | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (oldLock < 0) { *reason = @"old-store-lock"; return errSecNotAvailable; }
    } else if (errno != ENOENT) {
        *reason = @"old-store-directory"; return errSecNotAvailable;
    }
    OSStatus status = errSecSuccess;
    do {
        NSMutableArray *items = snapshot.items.mutableCopy;
        NSMutableOrderedSet *blocked = [NSMutableOrderedSet orderedSetWithArray:snapshot.blocked];
        LCKeychainSnapshot *old = oldLock >= 0 ? LCKeychainLoadStore(source, NO, YES, &status, reason) : nil;
        if (oldLock >= 0 && !old) break;
        if (old.split) {
            NSURL *oldV2 = [source URLByAppendingPathComponent:@"items-v2" isDirectory:YES];
            NSArray *entries = [NSFileManager.defaultManager contentsOfDirectoryAtPath:oldV2.path error:nil];
            NSSet *expected = [NSSet setWithArray:@[@"unlocked.plist", @"after-first-unlock.plist"]];
            if (!entries || ![[NSSet setWithArray:entries] isEqual:expected]) {
                status = errSecDecode; *reason = @"old-store-unexpected-files"; break;
            }
        }
        NSMutableDictionary *byIdentity = [NSMutableDictionary dictionary];
        for (NSDictionary *item in items) byIdentity[LCKeychainIdentity(item)] = item;
        for (NSDictionary *item in old.items) {
            NSArray *identity = LCKeychainIdentity(item);
            NSDictionary *current = byIdentity[identity];
            if (current) {
                // Do not silently discard either copy if the two stores diverged.
                NSMutableDictionary *legacy = item.mutableCopy;
                if (!legacy[LCKeychainRecordRef]) legacy[LCKeychainRecordRef] = current[LCKeychainRecordRef];
                if (![current isEqual:legacy]) { status = errSecDuplicateItem; *reason = @"old-store-record-conflict"; break; }
            } else {
                [items addObject:item];
            }
        }
        if (status != errSecSuccess) break;
        if (old.blocked.count) [blocked addObjectsFromArray:old.blocked];
        NSArray *verifiedItems = LCKeychainAssignReferences(items);
        if (oldLock >= 0) {
            status = LCKeychainSaveVerified(directory, store, verifiedItems, blocked.array, snapshot.migration, snapshot.split, reason);
            if (status != errSecSuccess) break;
            NSURL *v1 = [source URLByAppendingPathComponent:@"items-v1.plist"];
            NSURL *v2 = [source URLByAppendingPathComponent:@"items-v2" isDirectory:YES];
            NSURL *retired = [source URLByAppendingPathComponent:@"items-v2.retired" isDirectory:YES];
            NSFileManager *fm = NSFileManager.defaultManager;
            // Remove the stale v1 first, never leaving it visible after retiring authoritative v2.
            if ((unlink(v1.fileSystemRepresentation) != 0 && errno != ENOENT) ||
                (renameatx_np(AT_FDCWD, v2.fileSystemRepresentation, AT_FDCWD, retired.fileSystemRepresentation,
                    RENAME_EXCL) != 0 && errno != ENOENT)) {
                status = errSecNotAvailable; *reason = @"old-store-retire"; break;
            }
            NSError *error = nil;
            if (![fm removeItemAtURL:retired error:&error] &&
                !([error.domain isEqual:NSCocoaErrorDomain] && error.code == NSFileNoSuchFileError)) {
                status = errSecNotAvailable; *reason = @"old-store-cleanup"; break;
            }
        }
        NSMutableDictionary *state = snapshot.migration.mutableCopy;
        state[@"old-done"] = @YES;
        status = LCKeychainSaveVerified(directory, store, verifiedItems, blocked.array, state, oldLock >= 0 || snapshot.split, reason);
    } while (0);
    if (oldLock >= 0) close(oldLock);
    return status;
}

static NSDictionary *LCKeychainImportRecord(NSDictionary *native, NSString *itemClass) {
    NSDictionary *types = LCKeychainAttributeTypes(itemClass);
    NSMutableDictionary *candidate = [NSMutableDictionary dictionary];
    for (NSString *key in types) {
        id value = native[key];
        if (!value) continue;
        if (([key isEqual:KC(kSecAttrIsInvisible)] || [key isEqual:KC(kSecAttrIsNegative)]) &&
            [value isKindOfClass:NSNumber.class] && ([value isEqual:@0] || [value isEqual:@1])) value = @([value boolValue]);
        candidate[key] = value;
    }
    candidate[KC(kSecClass)] = itemClass;
    candidate[KC(kSecValueData)] = native[KC(kSecValueData)];
    candidate[KC(kSecAttrCreationDate)] = native[KC(kSecAttrCreationDate)] ?: NSDate.date;
    candidate[KC(kSecAttrModificationDate)] = native[KC(kSecAttrModificationDate)] ?: candidate[KC(kSecAttrCreationDate)];
    return LCKeychainValidateStore(@[candidate], nil, NULL) == errSecSuccess ? candidate : nil;
}

static NSDictionary *LCKeychainSystemIdentitySelector(NSDictionary *item) {
    NSString *itemClass = item[KC(kSecClass)];
    if ([item[KC(kSecAttrAccount)] isKindOfClass:NSData.class] || [item[KC(kSecAttrSynchronizable)] isEqual:@YES]) return nil;
    NSArray *keys = nil;
    if ([itemClass isEqual:KC(kSecClassGenericPassword)]) keys = @[KC(kSecAttrAccount), KC(kSecAttrService)];
    else if ([itemClass isEqual:KC(kSecClassInternetPassword)]) keys = @[
        KC(kSecAttrAccount), KC(kSecAttrServer), KC(kSecAttrSecurityDomain), KC(kSecAttrProtocol),
        KC(kSecAttrAuthenticationType), KC(kSecAttrPort), KC(kSecAttrPath)];
    else if ([itemClass isEqual:KC(kSecClassKey)]) keys = @[
        KC(kSecAttrKeyClass), KC(kSecAttrKeyType), KC(kSecAttrApplicationLabel), KC(kSecAttrApplicationTag)];
    else if ([itemClass isEqual:KC(kSecClassCertificate)]) keys = @[KC(kSecAttrIssuer), KC(kSecAttrSerialNumber)];
    else return nil;
    NSMutableDictionary *selector = [@{KC(kSecClass): itemClass} mutableCopy];
    for (NSString *key in keys) if (item[key]) selector[key] = item[key];
    return selector;
}

static NSDictionary *LCKeychainSystemRemoval(NSString *itemClass, NSDictionary *record, BOOL imported) {
    NSData *reference = record[KC(kSecValuePersistentRef)];
    if (!reference.length) return nil;
    NSMutableDictionary *job = [@{KC(kSecClass): itemClass, KC(kSecValuePersistentRef): reference} mutableCopy];
    if (imported) {
        NSDate *modified = record[KC(kSecAttrModificationDate)];
        if (modified) job[KC(kSecAttrModificationDate)] = modified;
    }
    return job;
}

static BOOL LCKeychainValidRemovals(id removals) {
    if (!removals) return YES;
    if (![removals isKindOfClass:NSArray.class]) return NO;
    for (id entry in removals) {
        if (![entry isKindOfClass:NSDictionary.class]) return NO;
        id itemClass = entry[KC(kSecClass)], reference = entry[KC(kSecValuePersistentRef)], date = entry[KC(kSecAttrModificationDate)];
        if (![itemClass isKindOfClass:NSString.class] || !LCKeychainAttributeTypes(itemClass) ||
            ![reference isKindOfClass:NSData.class] || ![reference length] ||
            (date && ![date isKindOfClass:NSDate.class])) return NO;
    }
    return YES;
}

static OSStatus LCKeychainDrainSystemRemovals(LCKeychainMigration *migration, NSMutableArray *jobs) {
    OSStatus firstError = errSecSuccess;
    for (NSDictionary *job in jobs.copy) {
        NSString *itemClass = job[KC(kSecClass)];
        NSData *reference = job[KC(kSecValuePersistentRef)];
        NSDate *expected = job[KC(kSecAttrModificationDate)];
        OSStatus status = errSecSuccess;
        if (expected) {
            NSArray *current = nil;
            status = migration.systemFind(@{KC(kSecClass): itemClass, KC(kSecValuePersistentRef): reference}, NO, &current);
            if (status == errSecSuccess && ![current.firstObject[KC(kSecAttrModificationDate)] isEqual:expected]) {
                status = errSecNotAvailable;
            }
        }
        if (status == errSecSuccess) status = migration.systemRemove(itemClass, reference);
        if (status == errSecSuccess || status == errSecItemNotFound) [jobs removeObject:job];
        else {
            LCKeychainLogMessage(@"migration-delete", itemClass, status, @"system-removal-pending");
            if (firstError == errSecSuccess) firstError = status;
        }
    }
    return firstError;
}

static BOOL LCKeychainSystemIsEmpty(LCKeychainMigration *migration) {
    for (NSString *itemClass in @[KC(kSecClassGenericPassword), KC(kSecClassInternetPassword),
        KC(kSecClassKey), KC(kSecClassCertificate)]) {
        NSArray *records = nil;
        OSStatus status = migration.systemFind(@{KC(kSecClass): itemClass}, NO, &records);
        if (status == errSecItemNotFound || (status == errSecSuccess && !records.count)) continue;
        if (status != errSecSuccess) LCKeychainLogMessage(@"migration-check", itemClass, status, @"system-inventory-unavailable");
        return NO;
    }
    return YES;
}

static OSStatus LCKeychainPerform(NSURL *directory, LCKeychainOperation operation, CFDictionaryRef input,
                                  CFDictionaryRef updates, CFTypeRef *result, NSArray<NSMutableDictionary *> *preparedKeys,
                                  LCKeychainLegacyRead legacyRead, LCKeychainMigration *migration, NSString *__strong *failureReason) {
    if (result) *result = NULL;
    NSString *op = @[@"add", @"copy", @"update", @"delete"][operation];
    NSDictionary *options = (__bridge NSDictionary *)input;
    NSString *itemClass = [options isKindOfClass:NSDictionary.class] ? options[KC(kSecClass)] : nil;
    if (!itemClass && [options isKindOfClass:NSDictionary.class]) {
        id reference = options[KC(kSecValueRef)];
        CFTypeID type = reference ? CFGetTypeID((__bridge CFTypeRef)reference) : 0;
        if (type == SecKeyGetTypeID()) itemClass = KC(kSecClassKey);
        else if (type == SecCertificateGetTypeID()) itemClass = KC(kSecClassCertificate);
        else if (type == SecIdentityGetTypeID()) itemClass = KC(kSecClassIdentity);
    }
    if (![options isKindOfClass:NSDictionary.class]) return errSecParam;
    id persistentInput = options[KC(kSecValuePersistentRef)];
    id matchList = options[KC(kSecMatchItemList)];
    BOOL hasPersistentSelector = persistentInput || matchList;
    NSArray *referenceList = [matchList isKindOfClass:NSArray.class] ? matchList : nil;
    if (!referenceList && persistentInput) referenceList = @[persistentInput];
    if (!itemClass) itemClass = LCKeychainRefClass(referenceList.firstObject);
    NSDictionary *types = [itemClass isKindOfClass:NSString.class] ? LCKeychainAttributeTypes(itemClass) : nil;
    NSString *className = types ? itemClass : @"unsupported";
    BOOL keyItem = [itemClass isEqual:KC(kSecClassKey)];
    BOOL identityItem = [itemClass isEqual:KC(kSecClassIdentity)];
    BOOL certificateItem = [itemClass isEqual:KC(kSecClassCertificate)] || identityItem;
    if (keyItem) className = @"key";
    if ([itemClass isEqual:KC(kSecClassCertificate)]) className = @"certificate";
    if ([itemClass isEqual:KC(kSecClassIdentity)]) className = @"identity";
    OSStatus (^fail)(OSStatus, NSString *) = ^OSStatus(OSStatus status, NSString *reason) {
        if (failureReason) *failureReason = reason;
        else if (status != errSecItemNotFound) LCKeychainLogMessage(op, className, status, reason);
        return status;
    };
    NSMutableSet<NSData *> *recordRefs = nil;
    if (hasPersistentSelector) {
        if (operation == LCKeychainAdd || options[KC(kSecValueRef)] || (persistentInput && matchList) ||
            !referenceList.count) return fail(errSecParam, @"invalid-persistent-selector");
        recordRefs = [NSMutableSet setWithCapacity:referenceList.count];
        for (id reference in referenceList) {
            NSString *referenceClass = LCKeychainRefClass(reference);
            if (!referenceClass) {
                if (!matchList && [reference isKindOfClass:NSData.class]) return errSecItemNotFound;
                return fail(errSecParam, @"unsupported-reference-list");
            }
            if (![referenceClass isEqual:itemClass]) return fail(errSecParam, @"persistent-reference-class-mismatch");
            [recordRefs addObject:identityItem ? LCKeychainRefWithClass(reference, KC(kSecClassCertificate)) : reference];
        }
    }
    if (!types) return fail(errSecParam, itemClass ? @"unsupported-class" : @"missing-class");
    BOOL importedTokenKey = operation == LCKeychainAdd && keyItem && options[KC(kSecAttrTokenID)] != nil;
    if (importedTokenKey) {
        id token = options[KC(kSecAttrTokenID)];
        if (![token isKindOfClass:NSString.class] || ![token length]) return fail(errSecParam, @"invalid-token-id");
        NSMutableDictionary *softwareOptions = options.mutableCopy;
        [softwareOptions removeObjectForKey:KC(kSecAttrTokenID)];
        [softwareOptions removeObjectForKey:KC(kSecAttrAccessControl)];
        [softwareOptions removeObjectForKey:KC(kSecAttrAccessible)];
        [softwareOptions removeObjectForKey:KC(kSecUseAuthenticationContext)];
        options = softwareOptions;
        LCKeychainLogMessage(op, className, errSecSuccess, @"token-key-add-software-emulated");
    }

    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    attributes[KC(kSecClass)] = itemClass;
    BOOL returnData = NO, returnAttributes = NO, returnRef = NO, returnPersistentRef = NO;
    BOOL passwordItem = !keyItem && !certificateItem;
    BOOL genericPassword = [itemClass isEqual:KC(kSecClassGenericPassword)];
    NSString *byteAttribute = genericPassword ? KC(kSecAttrGeneric) : (keyItem || identityItem) ? KC(kSecAttrApplicationTag) : nil;
    BOOL localPasswordRead = passwordItem && operation == LCKeychainCopy;
    BOOL localMetadataSelector = operation != LCKeychainAdd && options[KC(kSecAttrAccessControl)] != nil;
    BOOL allowLegacyRead = !localMetadataSelector;
    NSString *optionReason = nil;
    OSStatus optionStatus = LCKeychainNormalizeACL(&options, localPasswordRead, &optionReason);
    if (optionStatus != errSecSuccess) return fail(optionStatus, optionReason);
    id valueReference = nil;
    NSString *certificateEmail = nil, *certificateSubject = nil;
    NSDate *certificateDate = nil;
    NSSet<NSData *> *certificateIssuers = nil;
    SecPolicyRef certificatePolicy = NULL;
    BOOL ignoreSubjectCase = NO, trustedOnly = NO;
    NSDictionary *identityKey = nil;
    NSUInteger matchLimit = operation == LCKeychainCopy ? 1 : NSUIntegerMax;
    for (NSString *key in options) {
        if ([key isEqual:KC(kSecClass)]) continue;
        id value = options[key];
        if ([key isEqual:KC(kSecReturnData)] || [key isEqual:KC(kSecReturnAttributes)] ||
            [key isEqual:KC(kSecReturnRef)] || [key isEqual:KC(kSecReturnPersistentRef)]) {
            // SecItemDelete has no result; a redundant password return flag is not a selector.
            if (passwordItem && operation == LCKeychainDelete && [key isEqual:KC(kSecReturnAttributes)] &&
                LCKeychainIsBoolean(value)) continue;
            if ((operation != LCKeychainCopy && operation != LCKeychainAdd) || !LCKeychainIsBoolean(value)) return fail(errSecParam, LCKeychainSafeOption(key, value, types));
            if (![value boolValue]) continue;
            if ([key isEqual:KC(kSecReturnData)] && !identityItem) returnData = YES;
            else if ([key isEqual:KC(kSecReturnAttributes)]) returnAttributes = YES;
            else if ([key isEqual:KC(kSecReturnPersistentRef)]) returnPersistentRef = YES;
            else if ((keyItem || certificateItem) && [key isEqual:KC(kSecReturnRef)]) returnRef = YES;
            else return fail(errSecParam, LCKeychainSafeOption(key, value, types));
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        } else if ([key isEqual:KC(kSecUseAuthenticationUI)]) {
            BOOL skip = [value isEqual:KC(kSecUseAuthenticationUISkip)];
            if (operation != LCKeychainCopy && skip) {
                return fail(errSecParam, LCKeychainSafeOption(key, value, types));
            }
            BOOL standard = [value isEqual:KC(kSecUseAuthenticationUIAllow)] ||
                [value isEqual:KC(kSecUseAuthenticationUIFail)] || skip;
            if (!standard) {
                if (!localPasswordRead || (!LCKeychainIsBoolean(value) && ![value isKindOfClass:NSString.class])) {
                    return fail(errSecParam, LCKeychainSafeOption(key, value, types));
                }
                // LC's ordinary records need no UI. Do not interpret unknown modes for system items.
                allowLegacyRead = NO;
            }
        } else if ([key isEqual:KC(kSecUseNoAuthenticationUI)] || [key isEqual:KC(kSecUseOperationPrompt)]) {
            BOOL valid = [key isEqual:KC(kSecUseNoAuthenticationUI)] ?
                LCKeychainIsBoolean(value) : [value isKindOfClass:NSString.class];
            if (!valid) {
                return fail(errSecParam, LCKeychainSafeOption(key, value, types));
            }
            allowLegacyRead = NO;
#pragma clang diagnostic pop
        } else if ([key isEqual:KC(kSecUseAuthenticationContext)]) {
            if (![value isKindOfClass:LAContext.class]) return fail(errSecParam, LCKeychainSafeOption(key, value, types));
            // Ordinary LC records require no authentication. Do not change authentication behavior on system fallback.
            allowLegacyRead = NO;
        } else if ([key isEqual:KC(kSecUseDataProtectionKeychain)]) {
            // LC has one guest-local store; this iOS option does not select another store.
            if (!LCKeychainIsBoolean(value)) return fail(errSecParam, LCKeychainSafeOption(key, value, types));
        } else if ([key isEqual:KC(kSecAttrCreationDate)] || [key isEqual:KC(kSecAttrModificationDate)]) {
            if (operation == LCKeychainAdd || ![value isKindOfClass:NSDate.class]) {
                return fail(errSecParam, passwordItem ? @"invalid-password-date-selector" : @"invalid-date-selector");
            }
            // Dates returned by LC describe its local record, not a system record.
            attributes[key] = value;
            allowLegacyRead = NO;
            localMetadataSelector = YES;
        } else if ([key isEqual:KC(kSecValuePersistentRef)] || [key isEqual:KC(kSecMatchItemList)]) {
            continue; // Validated as a group before interpreting the other options.
        } else if ([key isEqual:KC(kSecMatchEmailAddressIfPresent)]) {
            if (!certificateItem || operation != LCKeychainCopy || ![value isKindOfClass:NSString.class] || ![value length]) {
                return fail(errSecParam, @"invalid-certificate-email-filter");
            }
            certificateEmail = value;
        } else if ([key isEqual:KC(kSecMatchSubjectContains)]) {
            if (!certificateItem || operation != LCKeychainCopy || ![value isKindOfClass:NSString.class] || ![value length]) {
                return fail(errSecParam, @"invalid-certificate-subject-filter");
            }
            certificateSubject = value;
        } else if ([key isEqual:KC(kSecMatchCaseInsensitive)] || [key isEqual:KC(kSecMatchTrustedOnly)]) {
            if (!certificateItem || operation != LCKeychainCopy || !LCKeychainIsBoolean(value)) {
                return fail(errSecParam, LCKeychainSafeOption(key, value, types));
            }
            if ([key isEqual:KC(kSecMatchCaseInsensitive)]) ignoreSubjectCase = [value boolValue];
            else trustedOnly = [value boolValue];
        } else if ([key isEqual:KC(kSecMatchPolicy)]) {
            if (!certificateItem || operation != LCKeychainCopy ||
                CFGetTypeID((__bridge CFTypeRef)value) != SecPolicyGetTypeID()) {
                return fail(errSecParam, @"invalid-certificate-policy-filter");
            }
            certificatePolicy = (__bridge SecPolicyRef)value;
        } else if ([key isEqual:KC(kSecMatchIssuers)]) {
            if (!certificateItem || operation != LCKeychainCopy || ![value isKindOfClass:NSArray.class] || ![value count]) {
                return fail(errSecParam, @"invalid-certificate-issuer-filter");
            }
            for (id name in value) {
                if (![name isKindOfClass:NSData.class] || ![name length]) return fail(errSecParam, @"invalid-certificate-issuer-filter");
            }
            certificateIssuers = [NSSet setWithArray:value];
        } else if ([key isEqual:KC(kSecMatchValidOnDate)]) {
            if (!certificateItem || operation != LCKeychainCopy ||
                (value != NSNull.null && ![value isKindOfClass:NSDate.class])) {
                return fail(errSecParam, @"invalid-certificate-date-filter");
            }
            if (@available(iOS 18.0, macOS 15.0, *)) {
                certificateDate = value == NSNull.null ? NSDate.date : value;
            } else {
                return fail(errSecUnimplemented, @"certificate-date-filter-unavailable");
            }
        } else if ([key isEqual:KC(kSecMatchLimit)]) {
            if (operation != LCKeychainCopy && operation != LCKeychainDelete) return fail(errSecParam, @"invalid-match-limit");
            if ([value isEqual:KC(kSecMatchLimitAll)]) matchLimit = NSUIntegerMax;
            else if ([value isEqual:KC(kSecMatchLimitOne)]) matchLimit = 1;
            else if ([value isKindOfClass:NSNumber.class] && !LCKeychainIsBoolean(value) &&
                     [value longLongValue] > 0 && [value isEqual:@([value longLongValue])]) {
                matchLimit = [value unsignedIntegerValue];
            } else return fail(errSecParam, @"unsupported-match-limit");
        } else if ((certificateItem || keyItem) && [key isEqual:KC(kSecValueRef)]) {
            valueReference = value;
        } else if ([key isEqual:byteAttribute] && [value isKindOfClass:NSString.class]) {
            id bytes = LCKeychainByteAttribute(value);
            if (!bytes) return fail(errSecParam, genericPassword ? @"invalid-generic-string-encoding" : @"invalid-application-tag");
            attributes[key] = bytes;
            if (genericPassword) allowLegacyRead = NO;
        } else if ((operation == LCKeychainAdd && [key isEqual:KC(kSecValueData)] && [value isKindOfClass:NSData.class]) ||
                   LCKeychainValidAttribute(key, value, types, operation != LCKeychainAdd)) {
            attributes[key] = value;
        } else {
            return fail(errSecParam, LCKeychainSafeOption(key, value, types));
        }
    }
    if (certificateItem && (operation == LCKeychainAdd || valueReference)) {
        if (valueReference && attributes[KC(kSecValueData)]) return fail(errSecParam, @"ambiguous-certificate-input");
        id certificate = valueReference;
        if (identityItem) {
            if (!valueReference || CFGetTypeID((__bridge CFTypeRef)valueReference) != SecIdentityGetTypeID()) {
                return fail(errSecParam, @"identity-reference-required");
            }
            SecIdentityRef identity = (__bridge SecIdentityRef)valueReference;
            SecCertificateRef cert = NULL;
            OSStatus status = SecIdentityCopyCertificate(identity, &cert);
            if (status != errSecSuccess || !cert) return fail(errSecDecode, @"identity-certificate-unavailable");
            certificate = CFBridgingRelease(cert);
            if (operation == LCKeychainAdd) {
                SecKeyRef key = NULL;
                status = SecIdentityCopyPrivateKey(identity, &key);
                if (status != errSecSuccess || !key) return fail(errSecDecode, @"identity-key-unavailable");
                id private = CFBridgingRelease(key);
                NSMutableDictionary *record = [@{KC(kSecClass): KC(kSecClassKey)} mutableCopy];
                for (NSString *name in LCKeychainAttributeTypes(KC(kSecClassKey))) {
                    if (attributes[name] && !LCKeychainAttributeTypes(KC(kSecClassCertificate))[name]) {
                        record[name] = attributes[name];
                        [attributes removeObjectForKey:name];
                    }
                }
                for (NSString *name in @[KC(kSecAttrAccessGroup), KC(kSecAttrAccessible), KC(kSecAttrSynchronizable)]) {
                    if (attributes[name]) record[name] = attributes[name];
                }
                NSString *keyReason = nil;
                status = LCKeychainPrepareKey(record, private, YES, &keyReason);
                if (status != errSecSuccess) return fail(status, keyReason);
                if (![record[KC(kSecAttrKeyClass)] isEqual:KC(kSecAttrKeyClassPrivate)]) {
                    return fail(errSecParam, @"identity-requires-private-key");
                }
                identityKey = record;
            }
        }
        if (operation == LCKeychainAdd) {
            OSStatus status = LCKeychainPrepareCertificate(attributes, certificate);
            if (status != errSecSuccess) return fail(status, @"invalid-certificate");
            if (identityItem && ![attributes[KC(kSecAttrPublicKeyHash)] isEqual:identityKey[KC(kSecAttrApplicationLabel)]]) {
                return fail(errSecParam, @"identity-key-mismatch");
            }
            attributes[KC(kSecClass)] = KC(kSecClassCertificate);
        } else {
            if (CFGetTypeID((__bridge CFTypeRef)certificate) != SecCertificateGetTypeID()) return fail(errSecParam, @"invalid-certificate-reference");
            attributes[KC(kSecValueData)] = CFBridgingRelease(SecCertificateCopyData((__bridge SecCertificateRef)certificate));
            if (!attributes[KC(kSecValueData)]) return fail(errSecDecode, @"invalid-certificate");
        }
    }
    if (keyItem && operation == LCKeychainAdd && !preparedKeys) {
        if ((valueReference && attributes[KC(kSecValueData)]) ||
            [attributes[KC(kSecAttrIsPermanent)] isEqual:@NO]) return fail(errSecParam, @"invalid-key-add");
        NSString *keyReason = nil;
        OSStatus status = LCKeychainPrepareKey(attributes, valueReference, NO, &keyReason);
        if (status != errSecSuccess) return fail(status, keyReason);
    } else if (keyItem && valueReference) {
        if (CFGetTypeID((__bridge CFTypeRef)valueReference) != SecKeyGetTypeID()) return fail(errSecParam, @"invalid-key-reference");
        NSDictionary *keyAttributes = CFBridgingRelease(SecKeyCopyAttributes((__bridge SecKeyRef)valueReference));
        if (!LCKeychainSoftwareKey(keyAttributes) || keyAttributes[KC(kSecAttrTokenID)]) {
            return fail(errSecUnimplemented, @"unsupported-key-reference");
        }
        for (NSString *name in @[KC(kSecAttrKeyType), KC(kSecAttrKeyClass), KC(kSecAttrApplicationLabel), KC(kSecAttrApplicationTag)]) {
            id value = keyAttributes[name];
            if (!value && [name isEqual:KC(kSecAttrApplicationTag)]) continue;
            if (!value) return fail(errSecDecode, @"incomplete-key-reference");
            if (attributes[name] && ![attributes[name] isEqual:value]) return errSecItemNotFound;
            attributes[name] = value;
        }
    }
    NSDictionary *changes = (__bridge NSDictionary *)updates;
    if (operation == LCKeychainUpdate) {
        if (![changes isKindOfClass:NSDictionary.class] || !changes.count) return fail(errSecParam, @"invalid-update");
        optionStatus = LCKeychainNormalizeACL(&changes, NO, &optionReason);
        if (optionStatus != errSecSuccess) return fail(optionStatus, optionReason);
        NSMutableDictionary *normalized = nil;
        // Dates returned by copy can be echoed in updates; the store owns both timestamps.
        for (NSString *key in @[KC(kSecAttrCreationDate), KC(kSecAttrModificationDate)]) {
            id value = changes[key];
            if (!value) continue;
            if (![value isKindOfClass:NSDate.class]) return fail(errSecParam, LCKeychainSafeOption(key, value, types));
            if (!normalized) normalized = changes.mutableCopy;
            [normalized removeObjectForKey:key];
        }
        id byteValue = byteAttribute ? changes[byteAttribute] : nil;
        if ([byteValue isKindOfClass:NSString.class]) {
            id bytes = LCKeychainByteAttribute(byteValue);
            if (!bytes) return fail(errSecParam, genericPassword ? @"invalid-generic-string-encoding" : @"invalid-application-tag");
            if (!normalized) normalized = changes.mutableCopy;
            normalized[byteAttribute] = bytes;
        }
        if (normalized) changes = normalized;
        for (NSString *key in changes) {
            id value = changes[key];
            BOOL syncChange = !identityItem && [key isEqual:KC(kSecAttrSynchronizable)];
            if (certificateItem && !syncChange && ![key isEqual:KC(kSecAttrLabel)] && ![key isEqual:KC(kSecAttrAccessible)]) {
                return fail(errSecUnimplemented, @"unsupported-certificate-update");
            }
            if (keyItem && !syncChange && ![key isEqual:KC(kSecAttrLabel)] && ![key isEqual:KC(kSecAttrApplicationTag)] &&
                ![key isEqual:KC(kSecAttrAccessible)]) return fail(errSecUnimplemented, @"unsupported-key-update");
            if ([key isEqual:KC(kSecValueData)] && [value isKindOfClass:NSData.class]) continue;
            if ([key isEqual:KC(kSecAttrAccessGroup)] || !LCKeychainValidAttribute(key, value, types, NO)) return fail(errSecParam, LCKeychainSafeOption(key, value, types));
        }
    }
    if ([attributes[KC(kSecAttrAccount)] isKindOfClass:NSData.class]) allowLegacyRead = NO;
    id sync = attributes[KC(kSecAttrSynchronizable)];
    BOOL requestsSync = [sync isEqual:@YES];
    if (operation != LCKeychainAdd) {
        if ([sync isEqual:KC(kSecAttrSynchronizableAny)]) [attributes removeObjectForKey:KC(kSecAttrSynchronizable)];
        else if (!sync && !hasPersistentSelector && !valueReference) attributes[KC(kSecAttrSynchronizable)] = @NO;
    }
    if (!directory) return fail(errSecNotAvailable, @"store-unavailable");
    NSFileManager *fm = NSFileManager.defaultManager;
    NSNumber *isDirectory = nil;
    NSNumber *isSymlink = nil;
    if (![fm createDirectoryAtURL:directory withIntermediateDirectories:YES
        attributes:@{NSFilePosixPermissions: @0700} error:nil] ||
        ![directory getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:nil] || !isDirectory.boolValue ||
        ![directory getResourceValue:&isSymlink forKey:NSURLIsSymbolicLinkKey error:nil] || isSymlink.boolValue ||
        ![directory setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil]) {
        return fail(errSecNotAvailable, @"store-directory");
    }
    NSURL *lockURL = [directory URLByAppendingPathComponent:@"items.lock"];
    int lock = open(lockURL.fileSystemRepresentation, O_CREAT | O_RDWR | O_EXLOCK | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0) return fail(errSecNotAvailable, @"store-lock");

    // Hold a separate lock across the read/modify/atomic-replace transaction.
    NSString *reason = nil;
    OSStatus status = errSecSuccess;
    id output = nil;
    NSDictionary *defaults = (keyItem || certificateItem) ? @{KC(kSecAttrSynchronizable): @NO} : LCKeychainPasswordDefaults(itemClass);
    NSDictionary *imported = nil;
    BOOL retriedOld = NO;
    BOOL retriedSystemRemovals = NO;
    for (;;) {
        NSURL *legacyFile = [directory URLByAppendingPathComponent:@"items-v1.plist"];
        NSURL *store = [directory URLByAppendingPathComponent:@"items-v2" isDirectory:YES];
        NSURL *unlockedFile = [store URLByAppendingPathComponent:@"unlocked.plist"];
        NSURL *afterFirstUnlockFile = [store URLByAppendingPathComponent:@"after-first-unlock.plist"];
        LCKeychainSnapshot *snapshot = LCKeychainLoadStore(directory, operation == LCKeychainCopy, NO, &status, &reason);
        if (!snapshot) break;
        BOOL partialRead = snapshot.partial;
        BOOL splitStore = snapshot.split;
        BOOL migrate = snapshot.v1;
        NSMutableDictionary *migrationState = snapshot.migration.mutableCopy;
        if (!LCKeychainValidRemovals(migrationState[@"removals"])) {
            status = errSecDecode; reason = @"invalid-system-removal-journal"; break;
        }
        NSMutableArray *removals = [migrationState[@"removals"] mutableCopy] ?: [NSMutableArray array];
        BOOL systemActive = migration.systemFind && migration.systemRemove && ![migrationState[@"system-done"] isEqual:@YES];
        BOOL oldActive = migration.oldDirectory && ![migrationState[@"old-done"] isEqual:@YES];
        if (!partialRead && systemActive && removals.count && !retriedSystemRemovals) {
            retriedSystemRemovals = YES;
            NSUInteger before = removals.count;
            LCKeychainDrainSystemRemovals(migration, removals);
            if (before != removals.count) {
                migrationState[@"removals"] = removals.count ? removals.copy : nil;
                if (!removals.count && LCKeychainSystemIsEmpty(migration)) migrationState[@"system-done"] = @YES;
                status = LCKeychainSaveVerified(directory, store, LCKeychainAssignReferences(snapshot.items), snapshot.blocked,
                    migrationState, splitStore, &reason);
                if (status != errSecSuccess) break;
                continue;
            }
        }
        if (oldActive && operation != LCKeychainCopy && !retriedOld) {
            status = LCKeychainRetireOldStore(directory, store, snapshot, migration.oldDirectory, &reason);
            if (status != errSecSuccess) break;
            retriedOld = YES;
            continue;
        }
        NSArray *existing = snapshot.items;
        NSArray *blocked = snapshot.blocked;
        NSMutableArray *items = existing.mutableCopy;
        NSMutableArray *legacyBlocked = blocked.mutableCopy;
        BOOL migrationDirty = NO;
        BOOL checkSystemEmpty = NO;
        BOOL systemDeleteMatched = NO;
        BOOL dirty = NO;
        NSIndexSet *updatedIndexes = nil;
        if (operation == LCKeychainAdd) {
            NSDate *now = NSDate.date;
            NSArray *newItems = preparedKeys ?:
                identityKey ? @[attributes, identityKey.mutableCopy] : @[attributes];
            if (identityKey) {
                // Reuse either component if it was already stored separately; never replace it.
                NSMutableDictionary *missing = [NSMutableDictionary dictionary];
                for (NSDictionary *item in newItems) missing[LCKeychainIdentity(item)] = item;
                for (NSDictionary *item in existing) {
                    NSArray *primaryKey = LCKeychainIdentity(item);
                    NSDictionary *candidate = missing[primaryKey];
                    if (!candidate) continue;
                    if (![item[KC(kSecValueData)] isEqual:candidate[KC(kSecValueData)]]) {
                        status = errSecDuplicateItem; reason = @"identity-component-conflict"; break;
                    }
                    [missing removeObjectForKey:primaryKey];
                    if (candidate == attributes) attributes = item.mutableCopy;
                    else identityKey = item;
                }
                if (status != errSecSuccess) break;
                if (!missing.count) { status = errSecDuplicateItem; reason = @"duplicate-identity"; break; }
                newItems = missing.allValues;
            }
            for (NSMutableDictionary *item in newItems) {
                item[KC(kSecAttrCreationDate)] = now;
                item[KC(kSecAttrModificationDate)] = now;
                if (!item[KC(kSecValueData)]) item[KC(kSecValueData)] = NSData.data;
                if (!item[KC(kSecAttrAccessible)]) item[KC(kSecAttrAccessible)] = KC(kSecAttrAccessibleWhenUnlocked);
                if (!item[KC(kSecAttrSynchronizable)]) item[KC(kSecAttrSynchronizable)] = @NO;
                if (!item[LCKeychainRecordRef]) item[LCKeychainRecordRef] = LCKeychainNewRef(item[KC(kSecClass)]);
                [items addObject:item];
            }
            if (result && returnPersistentRef && !attributes[LCKeychainRecordRef]) {
                NSUInteger index = [items indexOfObject:attributes];
                if (index == NSNotFound) { status = errSecDecode; reason = @"reference-restore-failed"; break; }
                attributes[LCKeychainRecordRef] = LCKeychainNewRef(attributes[KC(kSecClass)]);
                items[index] = attributes;
            }
            if (result) output = LCKeychainResult(attributes, identityKey, defaults, returnData, returnAttributes, returnRef, returnPersistentRef);
            if (result && (returnRef || returnPersistentRef) && !output) { status = errSecDecode; reason = @"reference-restore-failed"; break; }
        } else {
            // Index local certificate issuer links once. Traverse names, not item references.
            NSMutableDictionary<NSString *, NSMutableDictionary<NSData *, NSMutableSet<NSData *> *> *> *issuerLinks =
                certificateIssuers ? [NSMutableDictionary dictionary] : nil;
            if (issuerLinks) {
                for (NSDictionary *item in items) {
                    if (![item[KC(kSecClass)] isEqual:KC(kSecClassCertificate)]) continue;
                    NSString *group = item[KC(kSecAttrAccessGroup)] ?: @"";
                    NSData *subject = item[KC(kSecAttrSubject)], *issuer = item[KC(kSecAttrIssuer)];
                    if (!subject || !issuer || [subject isEqual:issuer]) continue;
                    if (!issuerLinks[group]) issuerLinks[group] = [NSMutableDictionary dictionary];
                    if (!issuerLinks[group][subject]) issuerLinks[group][subject] = [NSMutableSet set];
                    [issuerLinks[group][subject] addObject:issuer];
                }
            }
            NSMutableDictionary<NSArray *, NSMutableArray *> *privateKeys = identityItem ? [NSMutableDictionary dictionary] : nil;
            if (identityItem) {
                for (NSDictionary *item in items) {
                    if (![item[KC(kSecClass)] isEqual:KC(kSecClassKey)] ||
                        ![item[KC(kSecAttrKeyClass)] isEqual:KC(kSecAttrKeyClassPrivate)]) continue;
                    NSArray *pair = LCKeychainIdentityPair(item, KC(kSecAttrApplicationLabel));
                    if (!pair) continue;
                    if (!privateKeys[pair]) privateKeys[pair] = [NSMutableArray array];
                    [privateKeys[pair] addObject:item];
                }
            }
            NSMutableIndexSet *matches = [NSMutableIndexSet indexSet];
            NSMutableDictionary<NSNumber *, NSDictionary *> *matchedKeys = identityItem ? [NSMutableDictionary dictionary] : nil;
            BOOL requireUniqueKey = keyItem && valueReference && operation != LCKeychainCopy;
            [items enumerateObjectsUsingBlock:^(NSDictionary *item, NSUInteger index, BOOL *stop) {
                if (recordRefs && (!item[LCKeychainRecordRef] || ![recordRefs containsObject:item[LCKeychainRecordRef]])) return;
                NSDictionary *matchingKey = nil;
                if (identityItem) {
                    if (![item[KC(kSecClass)] isEqual:KC(kSecClassCertificate)]) return;
                    NSArray *pair = LCKeychainIdentityPair(item, KC(kSecAttrPublicKeyHash));
                    for (NSDictionary *key in pair ? privateKeys[pair] : nil) {
                        if (LCKeychainMatches(item, key, attributes, defaults)) { matchingKey = key; break; }
                    }
                    if (!matchingKey) return;
                } else if (!LCKeychainMatches(item, nil, attributes, defaults)) return;
                if (certificateIssuers) {
                    NSDictionary *links = issuerLinks[item[KC(kSecAttrAccessGroup)] ?: @""];
                    NSMutableSet *frontier = [NSMutableSet setWithObject:item[KC(kSecAttrIssuer)]];
                    NSMutableSet *visited = [NSMutableSet set];
                    BOOL found = NO;
                    for (NSUInteger depth = 0; frontier.count && depth <= 10; depth++) {
                        if ([frontier intersectsSet:certificateIssuers]) { found = YES; break; }
                        [visited unionSet:frontier];
                        NSMutableSet *next = [NSMutableSet set];
                        for (NSData *name in frontier) {
                            if (links[name]) [next unionSet:links[name]];
                        }
                        [next minusSet:visited];
                        frontier = next;
                    }
                    if (!found) return;
                }
                if ((certificateEmail || certificateDate || certificateSubject || certificatePolicy || trustedOnly) &&
                    !LCKeychainCertificateMatches(item[KC(kSecValueData)], certificateEmail, certificateDate,
                                                  certificateSubject, ignoreSubjectCase, certificatePolicy, trustedOnly)) return;
                if (matchingKey) matchedKeys[@(index)] = matchingKey;
                [matches addIndex:index];
                *stop = matches.count == (requireUniqueKey ? 2 : matchLimit);
            }];
            if (requireUniqueKey && matches.count > 1) { status = errSecParam; reason = @"ambiguous-key-reference"; break; }
            if (!partialRead && !matches.count && oldActive && !retriedOld) {
                status = LCKeychainRetireOldStore(directory, store, snapshot, migration.oldDirectory, &reason);
                if (status != errSecSuccess) break;
                retriedOld = YES;
                continue;
            }
            if (!partialRead && !matches.count && (legacyRead || systemActive) && localPasswordRead && allowLegacyRead &&
                matchLimit == 1 && !hasPersistentSelector && !requestsSync && !attributes[KC(kSecAttrAccessGroup)] &&
                attributes[KC(kSecAttrAccount)] && (attributes[KC(kSecAttrService)] || attributes[KC(kSecAttrServer)])) {
                BOOL blockedQuery = NO;
                for (NSDictionary *filter in blocked) {
                    if (LCKeychainMatches(attributes, nil, filter, @{})) { blockedQuery = YES; break; }
                }
                NSDictionary *legacy = nil;
                if (!blockedQuery && systemActive) {
                    NSArray *systemRecords = nil;
                    OSStatus findStatus = migration.systemFind(attributes, YES, &systemRecords);
                    if (findStatus == errSecSuccess) legacy = systemRecords.firstObject;
                    else if (findStatus != errSecItemNotFound) {
                        LCKeychainLogMessage(@"legacy-read", className, findStatus, @"system-read-failed");
                    }
                    checkSystemEmpty = findStatus == errSecItemNotFound || (findStatus == errSecSuccess && !legacy);
                } else if (!blockedQuery && legacyRead) legacy = legacyRead(attributes);
                NSMutableDictionary *candidate = nil;
                if (legacy) {
                    candidate = LCKeychainImportRecord(legacy, itemClass).mutableCopy;
                    if (!candidate || !LCKeychainMatches(candidate, nil, attributes, defaults)) {
                        LCKeychainLogMessage(@"legacy-import", className, errSecDecode, @"legacy-record-incompatible");
                        candidate = nil;
                    }
                }
                if (candidate) {
                    for (NSDictionary *filter in blocked) {
                        if (LCKeychainMatches(candidate, nil, filter, defaults)) {
                            candidate = nil;
                            break;
                        }
                    }
                    NSArray *identity = candidate ? LCKeychainIdentity(candidate) : nil;
                    for (NSDictionary *item in existing) {
                        if (identity && [LCKeychainIdentity(item) isEqual:identity]) { candidate = nil; break; }
                    }
                    if (candidate && systemActive) {
                        NSDictionary *job = LCKeychainSystemRemoval(itemClass, legacy, YES);
                        if (!job) { status = errSecDecode; reason = @"system-record-without-reference"; break; }
                        for (NSDictionary *pending in removals) {
                            if ([pending[KC(kSecValuePersistentRef)] isEqual:job[KC(kSecValuePersistentRef)]]) {
                                candidate = nil;
                                break;
                            }
                        }
                        if (candidate) {
                            [removals addObject:job];
                            migrationDirty = YES;
                        }
                    }
                    if (candidate) {
                        candidate[LCKeychainRecordRef] = LCKeychainNewRef(itemClass);
                        [matches addIndex:items.count];
                        [items addObject:candidate];
                        imported = candidate.copy;
                        dirty = YES;
                    }
                }
            }
            if (operation == LCKeychainDelete && systemActive && !requestsSync && !attributes[KC(kSecAttrAccessGroup)]) {
                NSMutableDictionary<NSDictionary *, NSArray *> *selectors = [NSMutableDictionary dictionary];
                NSMutableSet *matchedIdentities = [NSMutableSet set];
                [matches enumerateIndexesUsingBlock:^(NSUInteger index, BOOL *stop) {
                    NSDictionary *item = items[index];
                    if (item[KC(kSecAttrAccessGroup)]) return;
                    NSDictionary *selector = LCKeychainSystemIdentitySelector(item);
                    if (selector) {
                        NSArray *identity = LCKeychainIdentity(item);
                        selectors[selector] = identity;
                        [matchedIdentities addObject:identity];
                    }
                }];
                BOOL scanQuery = !hasPersistentSelector && !localMetadataSelector && !valueReference && allowLegacyRead &&
                    matchLimit > matches.count;
                if (scanQuery) selectors[attributes.copy] = @[];
                NSMutableDictionary<NSData *, NSDictionary *> *newJobs = [NSMutableDictionary dictionary];
                NSMutableSet *additional = [NSMutableSet set];
                for (NSDictionary *selector in selectors) {
                    NSArray *expectedIdentity = selectors[selector];
                    NSArray *nativeItems = nil;
                    status = migration.systemFind(selector, NO, &nativeItems);
                    if (status == errSecItemNotFound) { status = errSecSuccess; continue; }
                    if (status != errSecSuccess) { reason = @"system-delete-lookup"; break; }
                    for (NSDictionary *native in nativeItems) {
                        NSArray *identity = LCKeychainIdentity(native);
                        if (expectedIdentity.count && ![identity isEqual:expectedIdentity]) continue;
                        if (!expectedIdentity.count && ![matchedIdentities containsObject:identity] &&
                            ![additional containsObject:identity]) {
                            if (additional.count >= matchLimit - matches.count) continue;
                            [additional addObject:identity];
                        }
                        NSDictionary *job = LCKeychainSystemRemoval(selector[KC(kSecClass)], native, NO);
                        if (!job) { status = errSecDecode; reason = @"system-record-without-reference"; break; }
                        newJobs[job[KC(kSecValuePersistentRef)]] = job;
                    }
                    if (status != errSecSuccess) break;
                }
                if (status != errSecSuccess) break;
                if (newJobs.count) {
                    NSIndexSet *replaced = [removals indexesOfObjectsPassingTest:^BOOL(NSDictionary *job, NSUInteger idx, BOOL *stop) {
                        return newJobs[job[KC(kSecValuePersistentRef)]] != nil;
                    }];
                    [removals removeObjectsAtIndexes:replaced];
                    [removals addObjectsFromArray:newJobs.allValues];
                    dirty = migrationDirty = systemDeleteMatched = YES;
                } else if (selectors.count) checkSystemEmpty = YES;
            }
            if ((!migration || systemActive) && passwordItem && !requestsSync && !attributes[KC(kSecAttrAccessGroup)] &&
                (operation == LCKeychainDelete || (operation == LCKeychainUpdate && matches.count))) {
                if (operation == LCKeychainDelete && matchLimit == NSUIntegerMax && !localMetadataSelector &&
                    !hasPersistentSelector && ![legacyBlocked containsObject:attributes]) {
                    [legacyBlocked addObject:attributes.copy];
                    dirty = YES;
                }
                [matches enumerateIndexesUsingBlock:^(NSUInteger index, BOOL *stop) {
                    NSDictionary *item = items[index];
                    if (item[KC(kSecAttrAccessGroup)] || [item[KC(kSecAttrSynchronizable)] isEqual:@YES]) return;
                    NSMutableDictionary *filter = [@{KC(kSecClass): itemClass} mutableCopy];
                    for (NSString *key in LCKeychainPasswordDefaults(itemClass)) {
                        if (![key isEqual:KC(kSecAttrSynchronizable)]) filter[key] = item[key] ?: defaults[key];
                    }
                    if ([itemClass isEqual:KC(kSecClassGenericPassword)]) filter[KC(kSecAttrService)] = item[KC(kSecAttrService)] ?: @"";
                    if (![legacyBlocked containsObject:filter]) [legacyBlocked addObject:filter];
                }];
            }
            if (checkSystemEmpty && !removals.count && LCKeychainSystemIsEmpty(migration)) {
                migrationState[@"system-done"] = @YES;
                dirty = migrationDirty = YES;
            }
            if (!matches.count && !systemDeleteMatched) {
                if (partialRead) {
                    status = errSecInteractionNotAllowed; reason = @"store-locked"; break;
                }
                status = errSecItemNotFound; reason = @"item-not-found";
                if (!dirty) break;
            }
            if (operation == LCKeychainCopy) {
                if (result && (returnAttributes || returnData || returnRef || returnPersistentRef)) {
                    NSMutableArray *results = [NSMutableArray arrayWithCapacity:matches.count];
                    if (returnPersistentRef) {
                        for (NSUInteger index = matches.firstIndex; index != NSNotFound; index = [matches indexGreaterThanIndex:index]) {
                            if (items[index][LCKeychainRecordRef]) continue;
                            if (partialRead) {
                                status = errSecInteractionNotAllowed; reason = @"store-locked"; break;
                            }
                            NSMutableDictionary *item = [items[index] mutableCopy];
                            item[LCKeychainRecordRef] = LCKeychainNewRef(item[KC(kSecClass)]);
                            items[index] = item;
                            dirty = YES;
                        }
                        if (status != errSecSuccess) break;
                    }
                    [matches enumerateIndexesUsingBlock:^(NSUInteger index, BOOL *stop) {
                        id value = LCKeychainResult(items[index], matchedKeys[@(index)], defaults, returnData, returnAttributes, returnRef, returnPersistentRef);
                        if (value) [results addObject:value];
                        else *stop = YES;
                    }];
                    if (results.count != matches.count) { status = errSecDecode; reason = @"reference-restore-failed"; break; }
                    output = matchLimit == 1 ? results.firstObject : results.copy;
                }
                if (!dirty && !migrate) break;
            } else if (operation == LCKeychainDelete) {
                // An identity delete removes its certificate, not a possibly shared private key.
                [items removeObjectsAtIndexes:matches];
            } else {
                updatedIndexes = matches;
                NSDate *now = NSDate.date;
                [matches enumerateIndexesUsingBlock:^(NSUInteger index, BOOL *stop) {
                    NSMutableDictionary *item = [items[index] mutableCopy];
                    [item addEntriesFromDictionary:changes];
                    item[KC(kSecAttrModificationDate)] = now;
                    items[index] = item;
                }];
            }
        }
        NSString *conflict = nil;
        OSStatus validation = LCKeychainValidateStore(items, updatedIndexes, &conflict);
        if (validation != errSecSuccess) {
            status = validation;
            reason = conflict ?: (validation == errSecDuplicateItem ? @"duplicate-item" : @"store-invalid-write-records");
            if (updatedIndexes) {
                NSMutableArray<NSString *> *fields = [NSMutableArray array];
                // Only mutable identity fields can explain an update collision. Never log their values.
                NSArray<NSString *> *identityFields = passwordItem ? (genericPassword ? @[KC(kSecAttrAccount), KC(kSecAttrService)] :
                    @[KC(kSecAttrAccount), KC(kSecAttrServer), KC(kSecAttrSecurityDomain), KC(kSecAttrProtocol),
                      KC(kSecAttrAuthenticationType), KC(kSecAttrPort), KC(kSecAttrPath)]) :
                    keyItem ? @[KC(kSecAttrApplicationTag)] : @[];
                if (!identityItem) identityFields = [identityFields arrayByAddingObject:KC(kSecAttrSynchronizable)];
                for (NSString *field in identityFields) {
                    id value = changes[field];
                    if (!value) continue;
                    id defaultValue = [field isEqual:KC(kSecAttrApplicationTag)] ? NSData.data : defaults[field];
                    NSUInteger changed = [updatedIndexes indexPassingTest:^BOOL(NSUInteger index, BOOL *stop) {
                        return ![value isEqual:(existing[index][field] ?: defaultValue)];
                    }];
                    if (changed != NSNotFound) [fields addObject:field];
                }
                if (validation == errSecDecode) reason = @"store-invalid-update-records";
                reason = [NSString stringWithFormat:@"%@ matched=%lu identity-fields=%@", reason,
                    (unsigned long)updatedIndexes.count, fields.count ? [fields componentsJoinedByString:@","] : @"none"];
            }
            break;
        }
        if (migrationDirty) migrationState[@"removals"] = removals.count ? removals.copy : nil;
        OSStatus writeStatus = migrationDirty ? LCKeychainSaveVerified(directory, store, LCKeychainAssignReferences(items),
            legacyBlocked, migrationState, splitStore, &reason) :
            LCKeychainWriteStore(store, items, legacyBlocked, migrationState, splitStore, &reason);
        if (writeStatus != errSecSuccess) {
            if (migrate && !dirty && operation == LCKeychainCopy) {
                LCKeychainLogMessage(op, className, writeStatus, reason);
            } else {
                status = writeStatus;
            }
            break;
        }
        if (migrate && unlink(legacyFile.fileSystemRepresentation) != 0) {
            LCKeychainLogMessage(op, className, errSecNotAvailable, @"store-v1-cleanup");
        }
        if (imported) {
            NSURL *importedFile = LCKeychainAfterFirstUnlock(imported) ? afterFirstUnlockFile : unlockedFile;
            NSData *readBack = LCKeychainReadStore(importedFile, &status, &reason, NULL);
            if (!readBack) {
                if (status == errSecSuccess) status = errSecNotAvailable;
                reason = @"legacy-import-readback-failed";
                break;
            }
            id saved = [NSPropertyListSerialization propertyListWithData:readBack options:0 format:nil error:nil];
            NSArray *savedItems = [saved isKindOfClass:NSDictionary.class] ? saved[@"items"] : saved;
            if (![savedItems isKindOfClass:NSArray.class] || ![savedItems containsObject:imported]) {
                status = errSecDecode; reason = @"legacy-import-mismatch"; break;
            }
        }
        if (migrationDirty && removals.count && systemActive) {
            NSUInteger before = removals.count;
            OSStatus removeStatus = LCKeychainDrainSystemRemovals(migration, removals);
            if (before != removals.count) {
                migrationState[@"removals"] = removals.count ? removals.copy : nil;
                if (!removals.count && LCKeychainSystemIsEmpty(migration)) migrationState[@"system-done"] = @YES;
                OSStatus saveStatus = LCKeychainSaveVerified(directory, store, LCKeychainAssignReferences(items),
                    legacyBlocked, migrationState, YES, &reason);
                if (saveStatus != errSecSuccess) { status = saveStatus; break; }
            }
            if (operation == LCKeychainDelete && removeStatus != errSecSuccess) {
                status = removeStatus; reason = @"system-removal-pending";
            }
        }
        break;
    }
    close(lock);
    if (status != errSecSuccess) return fail(status, reason);
    if (imported) LCKeychainLogMessage(@"legacy-import", className, errSecSuccess, @"legacy-import-verified");
    if (result && output) *result = CFBridgingRetain(output);
    return status;
}

OSStatus LCManagedKeychainPerform(NSURL *directory, LCKeychainOperation operation,
                                  CFDictionaryRef input, CFDictionaryRef updates, CFTypeRef *result) {
    return LCKeychainPerform(directory, operation, input, updates, result, nil, nil, nil, NULL);
}

OSStatus LCManagedKeychainPerformWithLegacyRead(NSURL *directory, LCKeychainOperation operation,
    CFDictionaryRef input, CFDictionaryRef updates, CFTypeRef *result, LCKeychainLegacyRead legacyRead) {
    return LCKeychainPerform(directory, operation, input, updates, result, nil, legacyRead, nil, NULL);
}

OSStatus LCManagedKeychainPerformMigrating(NSURL *directory, LCKeychainMigration *migration,
    LCKeychainOperation operation, CFDictionaryRef input, CFDictionaryRef updates, CFTypeRef *result) {
    return LCKeychainPerform(directory, operation, input, updates, result, nil, nil, migration, NULL);
}

static NSString *LCKeychainKeyParameterReason(NSString *location, id key, id value, NSString *problem) {
    static NSCharacterSet *nonIdentifier;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        nonIdentifier = [NSCharacterSet characterSetWithCharactersInString:
            @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"].invertedSet;
    });
    NSString *field = [key isKindOfClass:NSString.class] && [key length] > 0 && [key length] <= 64 &&
        [key rangeOfCharacterFromSet:nonIdentifier].location == NSNotFound ? key : @"unavailable";
    return [NSString stringWithFormat:@"phase=parameters location=%@ field=%@ value-type=%@ issue=%@",
        location, field, value ? LCKeychainOptionValueType(value) : @"missing", problem];
}

static OSStatus LCKeychainParseKeyOptions(id input, BOOL import, NSDictionary **native,
    NSArray<NSDictionary *> **storage, BOOL *softwareToken, NSString **reason) {
    NSString *root = import ? @"import" : @"top";
    if (![input isKindOfClass:NSDictionary.class]) {
        *reason = LCKeychainKeyParameterReason(root, @"parameters", input, @"expected-dictionary");
        return errSecParam;
    }
    NSDictionary *options = input;
    NSString *privateAttrs = KC(kSecPrivateKeyAttrs), *publicAttrs = KC(kSecPublicKeyAttrs);
    NSString *token = KC(kSecAttrTokenID), *permanent = KC(kSecAttrIsPermanent);
    NSDictionary *privateOptions = options[privateAttrs], *publicOptions = options[publicAttrs];
    if (import && (privateOptions || publicOptions)) {
        *reason = LCKeychainKeyParameterReason(root, privateOptions ? privateAttrs : publicAttrs,
            privateOptions ?: publicOptions, @"unsupported-key-attributes-dictionary");
        return errSecUnimplemented;
    }
    if ((privateOptions && ![privateOptions isKindOfClass:NSDictionary.class]) ||
        (publicOptions && ![publicOptions isKindOfClass:NSDictionary.class])) {
        BOOL invalidPrivate = privateOptions && ![privateOptions isKindOfClass:NSDictionary.class];
        *reason = LCKeychainKeyParameterReason(root, invalidPrivate ? privateAttrs : publicAttrs,
            invalidPrivate ? privateOptions : publicOptions, @"expected-dictionary");
        return errSecParam;
    }
    *softwareToken = options[token] || privateOptions[token] || publicOptions[token];
    NSArray *levels = import ? @[options] : @[options, privateOptions ?: @{}, publicOptions ?: @{}];
    NSArray *locations = @[root, @"private", @"public"];
    NSDictionary *types = LCKeychainAttributeTypes(KC(kSecClassKey));
    NSMutableDictionary *crypto = [NSMutableDictionary dictionary];
    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    for (NSUInteger index = 0; index < levels.count; index++) {
        NSString *location = locations[index];
        NSDictionary *level = levels[index];
        if (!*softwareToken) {
            OSStatus status = LCKeychainNormalizeACL(&level, NO, reason);
            if (status != errSecSuccess) {
                NSString *field = levels[index][KC(kSecAttrAccessControl)] ? KC(kSecAttrAccessControl) : KC(kSecAttrAccessible);
                *reason = LCKeychainKeyParameterReason(location, field, levels[index][field], *reason);
                return status;
            }
        }
        NSMutableDictionary *record = [NSMutableDictionary dictionary];
        for (id field in level) {
            id value = level[field];
            BOOL valid = YES;
            if (!index && ([field isEqual:privateAttrs] || [field isEqual:publicAttrs])) continue;
            if ([field isEqual:KC(kSecClass)]) {
                // Key creation already fixes the item class, independently of the public/private key class.
                if ([KC(kSecClassKey) isEqual:value]) continue;
                *reason = LCKeychainKeyParameterReason(location, field, value, @"expected-key-item-class");
                return errSecParam;
            }
            if ([field isEqual:token]) {
                valid = [value isKindOfClass:NSString.class] && [value length] > 0;
            } else if ([field isEqual:KC(kSecAttrAccessControl)]) {
                valid = CFGetTypeID((__bridge CFTypeRef)value) == SecAccessControlGetTypeID();
            } else if ([field isEqual:KC(kSecUseAuthenticationContext)]) {
                valid = [value isKindOfClass:LAContext.class];
            } else if ([field isEqual:KC(kSecUseDataProtectionKeychain)]) {
                // Routing hints never select a different backend for an LC key.
                valid = LCKeychainIsBoolean(value);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            } else if ([field isEqual:KC(kSecUseNoAuthenticationUI)]) {
                valid = LCKeychainIsBoolean(value);
            } else if ([field isEqual:KC(kSecUseOperationPrompt)]) {
                valid = [value isKindOfClass:NSString.class];
            } else if ([field isEqual:KC(kSecUseAuthenticationUI)]) {
                valid = [value isEqual:KC(kSecUseAuthenticationUIAllow)] || [value isEqual:KC(kSecUseAuthenticationUIFail)];
#pragma clang diagnostic pop
            } else if ([field isEqual:KC(kSecAttrIsExtractable)] || (import && [field isEqual:permanent])) {
                valid = LCKeychainIsBoolean(value);
                if (valid) {
                    BOOL persistence = [field isEqual:permanent];
                    BOOL unsupported = persistence ? [value boolValue] : ![value boolValue];
                    if (unsupported) {
                        *reason = LCKeychainKeyParameterReason(location, field, value,
                            persistence ? @"use-SecItemAdd-to-persist-import" : @"nonexportable-software-key");
                        return errSecUnimplemented;
                    }
                }
            } else if ([field isEqual:KC(kSecAttrKeyType)] || [field isEqual:KC(kSecAttrKeyClass)] ||
                       [field isEqual:KC(kSecAttrKeySizeInBits)]) {
                valid = LCKeychainValidAttribute(field, value, types, NO) ||
                    (import && ![field isEqual:KC(kSecAttrKeySizeInBits)] && [value isKindOfClass:NSNumber.class] &&
                     !LCKeychainIsBoolean(value));
                // Generation always takes its algorithm and size from the top level.
                if (valid && !index && (import || ![field isEqual:KC(kSecAttrKeyClass)])) crypto[field] = value;
            } else if ([field isKindOfClass:NSString.class] && types[field]) {
                id normalized = [field isEqual:KC(kSecAttrApplicationTag)] ? LCKeychainByteAttribute(value) : value;
                valid = *softwareToken && [field isEqual:KC(kSecAttrAccessible)] ? [value isKindOfClass:NSString.class] :
                    LCKeychainValidAttribute(field, normalized, types, NO);
                if (valid && !import && !(*softwareToken && [field isEqual:KC(kSecAttrAccessible)])) record[field] = normalized;
            } else {
                *reason = LCKeychainKeyParameterReason(location, field, value, @"unsupported-key-option");
                return errSecUnimplemented;
            }
            if (!valid) {
                *reason = LCKeychainKeyParameterReason(location, field, value, @"invalid-value");
                return errSecParam;
            }
        }
        if (!import) [records addObject:record];
    }
    NSString *keyType = KC(kSecAttrKeyType), *shape = import ? KC(kSecAttrKeyClass) : KC(kSecAttrKeySizeInBits);
    if (!crypto[keyType] || !crypto[shape]) {
        *reason = LCKeychainKeyParameterReason(root, !crypto[keyType] ? keyType : shape, nil, @"missing-required-field");
        return errSecParam;
    }
    if (!import) {
        // No guest routing or persistence option reaches Security.framework.
        crypto[permanent] = @NO;
        NSMutableDictionary *privateRecord = [records[0] mutableCopy], *publicRecord = [records[0] mutableCopy];
        [privateRecord addEntriesFromDictionary:records[1]];
        [publicRecord addEntriesFromDictionary:records[2]];
        if (!privateRecord[permanent] && (options[token] || privateOptions[token])) privateRecord[permanent] = @YES;
        *storage = @[privateRecord, publicRecord];
    }
    *native = crypto;
    return errSecSuccess;
}

static SecKeyRef LCKeychainKeyFailure(NSString *operation, OSStatus status, NSString *reason,
                                      BOOL softwareToken, CFErrorRef *error) {
    LCKeychainLogMessage(operation, @"key", status, softwareToken ? [reason stringByAppendingString:@" backend=software-token"] : reason);
    if (error) *error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, status, NULL);
    return NULL;
}

SecKeyRef LCManagedCreateKeyWithData(CFDataRef data, CFDictionaryRef parameters, CFErrorRef *error) {
    if (error) *error = NULL;
    NSString *operation = @"SecKeyCreateWithData", *reason = nil;
    if (![(__bridge id)data isKindOfClass:NSData.class]) {
        reason = LCKeychainKeyParameterReason(@"import", @"keyData", (__bridge id)data, @"expected-data");
        return LCKeychainKeyFailure(operation, errSecParam, reason, NO, error);
    }
    NSDictionary *native = nil;
    BOOL softwareToken = NO;
    OSStatus status = LCKeychainParseKeyOptions((__bridge id)parameters, YES, &native, NULL, &softwareToken, &reason);
    if (status != errSecSuccess) return LCKeychainKeyFailure(operation, status, reason, softwareToken, error);
    CFErrorRef nativeError = NULL;
    SecKeyRef key = SecKeyCreateWithData(data, (__bridge CFDictionaryRef)native, &nativeError);
    if (!key) LCKeychainLogMessage(operation, @"key", LCKeyCreationErrorStatus(nativeError), @"phase=crypto issue=import-failed");
    else if (softwareToken) LCKeychainLogMessage(operation, @"key", errSecSuccess, @"token-key-import-software-emulated");
    else objc_setAssociatedObject((__bridge id)key, &LCKeychainOwnedSoftwareKeyMarker, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    if (error) *error = nativeError;
    else if (nativeError) CFRelease(nativeError);
    return key;
}

static SecKeyRef LCManagedGenerateSoftwareKey(NSURL *directory, NSString *operation, CFDictionaryRef parameters,
                                               SecKeyRef *publicKey, CFErrorRef *error) CF_RETURNS_RETAINED {
    if (publicKey) *publicKey = NULL;
    if (error) *error = NULL;
    NSString *reason = nil;
    NSDictionary *native = nil;
    NSArray<NSDictionary *> *storage = nil;
    BOOL softwareToken = NO;
    OSStatus status = LCKeychainParseKeyOptions((__bridge id)parameters, NO, &native, &storage, &softwareToken, &reason);
    if (status != errSecSuccess) return LCKeychainKeyFailure(operation, status, reason, softwareToken, error);

    CFErrorRef nativeError = NULL;
    SecKeyRef private = SecKeyCreateRandomKey((__bridge CFDictionaryRef)native, &nativeError);
    if (!private) {
        LCKeychainLogMessage(operation, @"key", LCKeyCreationErrorStatus(nativeError), @"phase=crypto issue=generate-failed");
        if (error) *error = nativeError;
        else if (nativeError) CFRelease(nativeError);
        return NULL;
    }
    if (nativeError) CFRelease(nativeError);
    NSString *permanent = KC(kSecAttrIsPermanent);
    BOOL storePublic = [storage[1][permanent] boolValue];
    SecKeyRef public = (publicKey || storePublic) ? SecKeyCopyPublicKey(private) : NULL;
    if ((publicKey || storePublic) && !public) {
        status = errSecInternalComponent;
        reason = @"phase=crypto location=public issue=public-key-unavailable";
    } else {
        objc_setAssociatedObject((__bridge id)private, &LCKeychainOwnedSoftwareKeyMarker, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        if (public) objc_setAssociatedObject((__bridge id)public, &LCKeychainOwnedSoftwareKeyMarker, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        NSMutableArray *prepared = [NSMutableArray arrayWithCapacity:2];
        for (NSUInteger index = 0; index < storage.count; index++) {
            if (![storage[index][permanent] boolValue]) continue;
            NSMutableDictionary *record = [storage[index] mutableCopy];
            record[KC(kSecClass)] = KC(kSecClassKey);
            status = LCKeychainPrepareKey(record, (__bridge id)(index ? public : private), NO, &reason);
            if (status != errSecSuccess) {
                reason = [NSString stringWithFormat:@"phase=store location=%@ issue=%@", index ? @"public" : @"private", reason];
                break;
            }
            [prepared addObject:record];
        }
        if (status == errSecSuccess && prepared.count) {
            NSDictionary *keyClass = @{KC(kSecClass): KC(kSecClassKey)};
            status = LCKeychainPerform(directory, LCKeychainAdd, (__bridge CFDictionaryRef)keyClass,
                NULL, NULL, prepared, nil, nil, &reason);
            if (status != errSecSuccess) reason = [@"phase=store issue=" stringByAppendingString:reason ?: @"persistent-key-store-failed"];
        }
    }
    if (status != errSecSuccess) {
        if (public) CFRelease(public);
        CFRelease(private);
        return LCKeychainKeyFailure(operation, status, reason, softwareToken, error);
    }
    if (publicKey) *publicKey = public;
    else if (public) CFRelease(public);
    if (softwareToken) LCKeychainLogMessage(operation, @"key", errSecSuccess, @"token-key-generation-software-emulated");
    return private;
}

SecKeyRef LCManagedCreateRandomKey(NSURL *directory, CFDictionaryRef parameters, CFErrorRef *error) {
    return LCManagedGenerateSoftwareKey(directory, @"SecKeyCreateRandomKey", parameters, NULL, error);
}

OSStatus LCManagedGenerateKeyPair(NSURL *directory, CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey) {
    if (privateKey) *privateKey = NULL;
    // Use the modern non-persisting API even for callers of the legacy function.
    CFErrorRef error = NULL;
    SecKeyRef private = LCManagedGenerateSoftwareKey(directory, @"SecKeyGeneratePair", parameters, publicKey, &error);
    if (!private) {
        OSStatus status = LCKeyCreationErrorStatus(error);
        if (error) CFRelease(error);
        return status;
    }
    if (privateKey) *privateKey = private;
    else CFRelease(private);
    return errSecSuccess;
}
