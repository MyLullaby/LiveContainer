#import "LCManagedKeychain.h"
#import "LCDebugLog.h"
#import <objc/runtime.h>
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

static OSStatus LCValidateTemporaryKeyOptions(id input, BOOL allowKeyDictionaries, BOOL softwareToken,
                                              NSDictionary **validated, NSString **reason) {
    NSDictionary *options = [input isKindOfClass:NSDictionary.class] ? [input copy] : nil;
    if (![options isKindOfClass:NSDictionary.class]) {
        *reason = @"invalid-key-parameters";
        return errSecParam;
    }
    static NSSet *softwareOptions;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        softwareOptions = [NSSet setWithArray:@[KC(kSecAttrKeyType), KC(kSecAttrKeyClass),
            KC(kSecAttrKeySizeInBits), KC(kSecAttrEffectiveKeySize), KC(kSecAttrLabel),
            KC(kSecAttrApplicationTag), KC(kSecAttrCanEncrypt), KC(kSecAttrCanDecrypt),
            KC(kSecAttrCanDerive), KC(kSecAttrCanSign), KC(kSecAttrCanVerify),
            KC(kSecAttrCanWrap), KC(kSecAttrCanUnwrap)]];
    });
    NSMutableDictionary *safe = options.mutableCopy;
    for (id key in options) {
        id value = options[key];
        if ([key isEqual:KC(kSecAttrIsPermanent)]) {
            if (!LCKeychainIsBoolean(value)) {
                *reason = @"invalid-key-permanence";
                return errSecParam;
            }
            if (![value boolValue]) continue;
            *reason = @"persistent-key";
        } else if ([key isEqual:KC(kSecPublicKeyAttrs)] || [key isEqual:KC(kSecPrivateKeyAttrs)]) {
            if (allowKeyDictionaries) {
                NSDictionary *child = nil;
                OSStatus status = LCValidateTemporaryKeyOptions(value, NO, softwareToken, &child, reason);
                if (status != errSecSuccess) return status;
                safe[key] = child;
                continue;
            }
            *reason = @"unsupported-key-attributes-dictionary";
        } else if ([key isEqual:KC(kSecAttrTokenID)]) {
            if (![value isKindOfClass:NSString.class] || ![value length]) {
                *reason = @"invalid-token-id";
                return errSecParam;
            }
            if (!softwareToken) {
                *reason = [value isEqual:KC(kSecAttrTokenIDSecureEnclave)] ? @"secure-enclave-token" : @"unsupported-token-id";
            } else {
                [safe removeObjectForKey:key];
                continue;
            }
        } else if ([key isEqual:KC(kSecAttrAccessControl)] || [key isEqual:KC(kSecAttrAccessible)] ||
                   [key isEqual:KC(kSecUseAuthenticationContext)]) {
            if (softwareToken) {
                [safe removeObjectForKey:key];
                continue;
            }
            *reason = @"protected-key";
        } else if ([softwareOptions containsObject:key]) {
            continue;
        } else {
            *reason = @"unsupported-key-option";
        }
        return errSecUnimplemented;
    }
    if (allowKeyDictionaries) safe[KC(kSecAttrIsPermanent)] = @NO;
    *validated = safe.copy;
    return errSecSuccess;
}

static OSStatus LCKeyCreationErrorStatus(CFErrorRef error) {
    return error && CFEqual(CFErrorGetDomain(error), kCFErrorDomainOSStatus) ?
        (OSStatus)CFErrorGetCode(error) : errSecInternalComponent;
}

static NSString *LCKeychainFailureReason(NSString *reason, BOOL softwareToken) {
    return softwareToken && ![reason hasPrefix:@"token-"] ? [@"token-" stringByAppendingString:reason] : reason;
}

static BOOL LCKeychainTokenRequest(NSDictionary *parameters) {
    if (parameters[KC(kSecAttrTokenID)]) return YES;
    for (NSString *key in @[KC(kSecPrivateKeyAttrs), KC(kSecPublicKeyAttrs)]) {
        NSDictionary *child = parameters[key];
        if ([child isKindOfClass:NSDictionary.class] && child[KC(kSecAttrTokenID)]) return YES;
    }
    return NO;
}

static SecKeyRef LCManagedCreateTemporaryKey(NSString *operation, BOOL import, CFDataRef data,
                                            BOOL softwareToken, CFDictionaryRef parameters, CFErrorRef *error) {
    if (error) *error = NULL;
    NSString *reason = nil;
    NSDictionary *validated = nil;
    OSStatus status;
    if (import && ![(__bridge id)data isKindOfClass:NSData.class]) {
        status = errSecParam;
        reason = @"invalid-key-data";
    } else {
        status = LCValidateTemporaryKeyOptions((__bridge id)parameters, !import, softwareToken, &validated, &reason);
    }
    if (status != errSecSuccess) {
        LCKeychainLogMessage(operation, @"key", status, LCKeychainFailureReason(reason, softwareToken));
        if (error) *error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, status, NULL);
        return NULL;
    }

    CFErrorRef systemError = NULL;
    CFDictionaryRef safeParameters = (__bridge CFDictionaryRef)validated;
    SecKeyRef key = import ? SecKeyCreateWithData(data, safeParameters, &systemError) :
        SecKeyCreateRandomKey(safeParameters, &systemError);
    if (!key) LCKeychainLogMessage(operation, @"key", LCKeyCreationErrorStatus(systemError),
        softwareToken ? @"token-temporary-key-create-failed" : @"temporary-key-create-failed");
    else if (softwareToken && import) LCKeychainLogMessage(operation, @"key", errSecSuccess, @"token-key-import-software-emulated");
    if (error) *error = systemError;
    else if (systemError) CFRelease(systemError);
    return key;
}

SecKeyRef LCManagedCreateKeyWithData(CFDataRef data, CFDictionaryRef parameters, CFErrorRef *error) {
    NSDictionary *input = [(__bridge id)parameters isKindOfClass:NSDictionary.class] ? (__bridge NSDictionary *)parameters : nil;
    BOOL softwareToken = input && LCKeychainTokenRequest(input);
    SecKeyRef key = LCManagedCreateTemporaryKey(@"SecKeyCreateWithData", YES, data, softwareToken, parameters, error);
    // Security can report a memory-only import as permanent. Track the exact object, not its key material.
    if (key && !softwareToken) objc_setAssociatedObject((__bridge id)key, &LCKeychainOwnedSoftwareKeyMarker, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return key;
}

static BOOL LCKeychainValidAttribute(NSString *key, id value, NSDictionary *types, BOOL query) {
    Class expected = types[key];
    if (!expected || ![value isKindOfClass:expected]) return NO;
    if ([key isEqualToString:KC(kSecAttrSynchronizable)]) {
        return (LCKeychainIsBoolean(value) && ![value boolValue]) ||
            (query && (LCKeychainIsBoolean(value) || [value isEqual:KC(kSecAttrSynchronizableAny)]));
    }
    if ([key isEqualToString:KC(kSecAttrAccessible)]) {
        return [value isEqual:KC(kSecAttrAccessibleWhenUnlocked)] || [value isEqual:KC(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)] ||
            [value isEqual:KC(kSecAttrAccessibleAfterFirstUnlock)] || [value isEqual:KC(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)];
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

static OSStatus LCKeychainNormalizePasswordACL(NSDictionary *__strong *input, NSString **reason) {
    id control = (*input)[KC(kSecAttrAccessControl)];
    if (!control) return errSecSuccess;
    CFTypeRef reference = (__bridge CFTypeRef)control;
    if (CFGetTypeID(reference) != SecAccessControlGetTypeID()) {
        *reason = @"invalid-password-access-control-type";
        return errSecParam;
    }
    for (NSString *protection in @[KC(kSecAttrAccessibleWhenUnlocked), KC(kSecAttrAccessibleAfterFirstUnlock),
                                   KC(kSecAttrAccessibleWhenUnlockedThisDeviceOnly), KC(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)]) {
        // Only an exact match to a no-flags ACL can use the store's accessibility policy.
        SecAccessControlRef ordinary = SecAccessControlCreateWithFlags(NULL, (__bridge CFTypeRef)protection, 0, NULL);
        BOOL matches = ordinary && CFEqual(reference, ordinary);
        if (ordinary) CFRelease(ordinary);
        if (!matches) continue;
        id accessible = (*input)[KC(kSecAttrAccessible)];
        if (accessible && ![accessible isEqual:protection]) {
            *reason = @"conflicting-password-access-control";
            return errSecParam;
        }
        NSMutableDictionary *normalized = [*input mutableCopy];
        [normalized removeObjectForKey:KC(kSecAttrAccessControl)];
        normalized[KC(kSecAttrAccessible)] = protection;
        *input = normalized.copy;
        return errSecSuccess;
    }
    *reason = @"password-access-control-not-supported";
    return errSecUnimplemented;
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
    NSString *valueType = @"other";
    if ([value isKindOfClass:NSString.class]) valueType = @"string";
    else if (LCKeychainIsBoolean(value)) valueType = @"boolean";
    else if ([value isKindOfClass:NSNumber.class]) valueType = @"number";
    else if ([value isKindOfClass:NSData.class]) valueType = @"data";
    else if ([value isKindOfClass:NSDate.class]) valueType = @"date";
    else if ([value isKindOfClass:NSArray.class]) valueType = @"array";
    else if ([value isKindOfClass:NSDictionary.class]) valueType = @"dictionary";
    else if (value == NSNull.null) valueType = @"null";
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
    if ([item[KC(kSecClass)] isEqual:KC(kSecClassKey)]) {
        return @[item[KC(kSecClass)], item[KC(kSecAttrAccessGroup)] ?: @"", item[KC(kSecAttrKeyClass)],
            item[KC(kSecAttrKeyType)], item[KC(kSecAttrApplicationLabel)], item[KC(kSecAttrApplicationTag)] ?: NSData.data];
    }
    if ([item[KC(kSecClass)] isEqual:KC(kSecClassCertificate)]) {
        return @[item[KC(kSecClass)], item[KC(kSecAttrAccessGroup)] ?: @"",
            item[KC(kSecAttrIssuer)], item[KC(kSecAttrSerialNumber)]];
    }
    NSArray *common = @[item[KC(kSecClass)], item[KC(kSecAttrAccessGroup)] ?: @"", item[KC(kSecAttrAccount)] ?: @""];
    if ([item[KC(kSecClass)] isEqual:KC(kSecClassGenericPassword)]) {
        return [common arrayByAddingObject:item[KC(kSecAttrService)] ?: @""];
    }
    return [common arrayByAddingObjectsFromArray:@[
        item[KC(kSecAttrServer)] ?: @"", item[KC(kSecAttrSecurityDomain)] ?: @"",
        item[KC(kSecAttrProtocol)] ?: @"", item[KC(kSecAttrAuthenticationType)] ?: KC(kSecAttrAuthenticationTypeDefault),
        item[KC(kSecAttrPort)] ?: @0, item[KC(kSecAttrPath)] ?: @"",
    ]];
}

static BOOL LCKeychainValidStore(NSArray *items) {
    if (![items isKindOfClass:NSArray.class]) return NO;
    NSMutableSet *identities = [NSMutableSet set];
    for (NSDictionary *item in items) {
        if (![item isKindOfClass:NSDictionary.class]) return NO;
        NSString *itemClass = item[KC(kSecClass)];
        NSDictionary *types = [itemClass isKindOfClass:NSString.class] ? LCKeychainAttributeTypes(itemClass) : nil;
        if (!types || [itemClass isEqual:KC(kSecClassIdentity)] || ![item[KC(kSecValueData)] isKindOfClass:NSData.class] ||
            ![item[KC(kSecAttrCreationDate)] isKindOfClass:NSDate.class] ||
            ![item[KC(kSecAttrModificationDate)] isKindOfClass:NSDate.class] || !item[KC(kSecAttrAccessible)]) return NO;
        for (NSString *key in item) {
            if ([key isEqual:KC(kSecClass)] || [key isEqual:KC(kSecValueData)] ||
                [key isEqual:KC(kSecAttrCreationDate)] || [key isEqual:KC(kSecAttrModificationDate)]) continue;
            if ([key isEqual:LCKeychainRecordRef] && [item[key] isKindOfClass:NSData.class]) continue;
            if (!LCKeychainValidAttribute(key, item[key], types, NO)) return NO;
        }
        if ([itemClass isEqual:KC(kSecClassKey)] && (!LCKeychainSoftwareKey(item) ||
            ![item[KC(kSecAttrApplicationLabel)] length] || ![item[KC(kSecAttrIsPermanent)] boolValue] ||
            ![item[KC(kSecValueData)] length])) return NO;
        if ([itemClass isEqual:KC(kSecClassCertificate)] && (!item[KC(kSecAttrIssuer)] ||
            ![item[KC(kSecAttrSerialNumber)] length] || ![item[KC(kSecValueData)] length])) return NO;
        NSArray *identity = LCKeychainIdentity(item);
        if ([identities containsObject:identity]) return NO;
        [identities addObject:identity];
    }
    return YES;
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
    if (returnAttributes && privateKey) result[KC(kSecClass)] = KC(kSecClassIdentity);
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
        if (![query[attribute] isEqual:(item[attribute] ?: key[attribute] ?: defaults[attribute])]) return NO;
    }
    return YES;
}

static BOOL LCKeychainCertificateMatches(NSData *data, NSString *email, NSDate *date) {
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
    CFRelease(certificate);
    return matches;
}

static BOOL LCKeychainAfterFirstUnlock(NSDictionary *item) {
    NSString *protection = item[KC(kSecAttrAccessible)];
    return [protection isEqual:KC(kSecAttrAccessibleAfterFirstUnlock)] ||
        [protection isEqual:KC(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)];
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

static OSStatus LCKeychainWriteStore(NSURL *store, NSArray *items, NSArray *blocked, BOOL replace,
                                     NSString **reason) {
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
    NSArray *documents = @[@{@"items": unlocked, @"legacy-blocked": blocked}, afterFirstUnlock];
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
    unlockedOptions = unlocked.count || blocked.count ? NSDataWritingFileProtectionComplete : afterFirstUnlockOptions;
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

static OSStatus LCKeychainPerform(NSURL *directory, LCKeychainOperation operation, CFDictionaryRef input,
                                  CFDictionaryRef updates, CFTypeRef *result, NSDictionary *additionalKey,
                                  LCKeychainLegacyRead legacyRead) {
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
        if (status != errSecItemNotFound) LCKeychainLogMessage(op, className, status, reason);
        return status;
    };
    NSMutableSet<NSData *> *recordRefs = nil;
    if (hasPersistentSelector) {
        if (operation == LCKeychainAdd || options[KC(kSecValueRef)] || (persistentInput && matchList) ||
            (!persistentInput && operation != LCKeychainCopy && operation != LCKeychainDelete) ||
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
    BOOL localPasswordRead = passwordItem && operation == LCKeychainCopy;
    BOOL localMetadataSelector = passwordItem && operation != LCKeychainAdd && options[KC(kSecAttrAccessControl)] != nil;
    BOOL allowLegacyRead = !localMetadataSelector;
    if (passwordItem) {
        NSString *reason = nil;
        OSStatus status = LCKeychainNormalizePasswordACL(&options, &reason);
        if (status != errSecSuccess) return fail(status, reason);
    }
    id valueReference = nil;
    NSString *certificateEmail = nil;
    NSDate *certificateDate = nil;
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
            if (operation != LCKeychainCopy && (!passwordItem || skip)) {
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
            if (!passwordItem || !valid) {
                return fail(errSecParam, LCKeychainSafeOption(key, value, types));
            }
            allowLegacyRead = NO;
#pragma clang diagnostic pop
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
        } else if (genericPassword && [key isEqual:KC(kSecAttrGeneric)] && [value isKindOfClass:NSString.class]) {
            NSData *genericData = [value dataUsingEncoding:NSUTF8StringEncoding];
            if (!genericData) return fail(errSecParam, @"invalid-generic-string-encoding");
            attributes[key] = genericData;
            allowLegacyRead = NO;
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
                for (NSString *name in @[KC(kSecAttrAccessGroup), KC(kSecAttrAccessible)]) {
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
    if (keyItem && operation == LCKeychainAdd) {
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
        if (passwordItem) {
            NSString *reason = nil;
            OSStatus status = LCKeychainNormalizePasswordACL(&changes, &reason);
            if (status != errSecSuccess) return fail(status, reason);
        }
        id genericValue = changes[KC(kSecAttrGeneric)];
        if (genericPassword && [genericValue isKindOfClass:NSString.class]) {
            NSData *genericData = [genericValue dataUsingEncoding:NSUTF8StringEncoding];
            if (!genericData) return fail(errSecParam, @"invalid-generic-string-encoding");
            NSMutableDictionary *normalized = changes.mutableCopy;
            normalized[KC(kSecAttrGeneric)] = genericData;
            changes = normalized;
        }
        for (NSString *key in changes) {
            id value = changes[key];
            if (certificateItem && ![key isEqual:KC(kSecAttrLabel)] && ![key isEqual:KC(kSecAttrAccessible)]) {
                return fail(errSecUnimplemented, @"unsupported-certificate-update");
            }
            if (keyItem && ![key isEqual:KC(kSecAttrLabel)] && ![key isEqual:KC(kSecAttrApplicationTag)] &&
                ![key isEqual:KC(kSecAttrAccessible)]) return fail(errSecUnimplemented, @"unsupported-key-update");
            if ([key isEqual:KC(kSecValueData)] && [value isKindOfClass:NSData.class]) continue;
            if ([key isEqual:KC(kSecAttrAccessGroup)] || !LCKeychainValidAttribute(key, value, types, NO)) return fail(errSecParam, LCKeychainSafeOption(key, value, types));
        }
    }
    BOOL requestsSync = [attributes[KC(kSecAttrSynchronizable)] isEqual:@YES];
    if (operation != LCKeychainAdd && [attributes[KC(kSecAttrSynchronizable)] isEqual:KC(kSecAttrSynchronizableAny)]) {
        [attributes removeObjectForKey:KC(kSecAttrSynchronizable)];
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
    do {
        NSURL *legacyFile = [directory URLByAppendingPathComponent:@"items-v1.plist"];
        NSURL *store = [directory URLByAppendingPathComponent:@"items-v2" isDirectory:YES];
        NSURL *unlockedFile = [store URLByAppendingPathComponent:@"unlocked.plist"];
        NSURL *afterFirstUnlockFile = [store URLByAppendingPathComponent:@"after-first-unlock.plist"];
        struct stat storeInfo;
        BOOL splitStore = lstat(store.fileSystemRepresentation, &storeInfo) == 0;
        if ((splitStore && !S_ISDIR(storeInfo.st_mode)) || (!splitStore && errno != ENOENT)) {
            status = errSecNotAvailable; reason = @"store-directory"; break;
        }
        BOOL unlockedDenied = NO;
        NSData *data = LCKeychainReadStore(splitStore ? unlockedFile : legacyFile, &status, &reason, &unlockedDenied);
        BOOL partialRead = splitStore && unlockedDenied && operation == LCKeychainCopy;
        if (partialRead) status = errSecSuccess;
        if (status != errSecSuccess) break;
        if (splitStore && !data && !partialRead) {
            status = errSecDecode; reason = @"store-missing-unlocked"; break;
        }
        id decoded = data ? [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil] : @[];
        BOOL hasMetadata = [decoded isKindOfClass:NSDictionary.class];
        NSArray *existing = hasMetadata ? decoded[@"items"] : decoded;
        NSArray *blocked = hasMetadata ? decoded[@"legacy-blocked"] : @[];
        if (!LCKeychainValidStore(existing) || ![blocked isKindOfClass:NSArray.class]) {
            status = errSecDecode; reason = @"store-invalid-records"; break;
        }
        for (id entry in blocked) {
            if (![entry isKindOfClass:NSDictionary.class]) { status = errSecDecode; break; }
            NSDictionary *filter = entry;
            id filterClass = filter[KC(kSecClass)];
            if (![filterClass isEqual:KC(kSecClassGenericPassword)] && ![filterClass isEqual:KC(kSecClassInternetPassword)]) {
                status = errSecDecode;
                break;
            }
            NSDictionary *filterTypes = LCKeychainAttributeTypes(filterClass);
            for (NSString *key in filter) {
                if (![key isEqual:KC(kSecClass)] && !LCKeychainValidAttribute(key, filter[key], filterTypes, YES)) {
                    status = errSecDecode;
                    break;
                }
            }
            if (status != errSecSuccess) break;
        }
        if (status != errSecSuccess) { reason = @"store-invalid-legacy-filters"; break; }
        if (splitStore) {
            NSData *afterData = LCKeychainReadStore(afterFirstUnlockFile, &status, &reason, NULL);
            if (status != errSecSuccess) break;
            id afterItems = afterData ? [NSPropertyListSerialization propertyListWithData:afterData
                options:0 format:nil error:nil] : nil;
            if (![afterItems isKindOfClass:NSArray.class]) {
                status = errSecDecode; reason = @"store-invalid-after-first-unlock"; break;
            }
            existing = [existing arrayByAddingObjectsFromArray:afterItems];
            if (!LCKeychainValidStore(existing)) {
                status = errSecDecode; reason = @"store-invalid-records"; break;
            }
        }
        NSMutableArray *items = existing.mutableCopy;
        NSMutableArray *legacyBlocked = blocked.mutableCopy;
        BOOL migrate = !splitStore && data != nil;
        BOOL dirty = NO;
        if (operation == LCKeychainAdd) {
            NSDate *now = NSDate.date;
            NSArray *newItems = additionalKey ? @[attributes, additionalKey.mutableCopy] :
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
                if ((certificateEmail || certificateDate) &&
                    !LCKeychainCertificateMatches(item[KC(kSecValueData)], certificateEmail, certificateDate)) return;
                if (matchingKey) matchedKeys[@(index)] = matchingKey;
                [matches addIndex:index];
                *stop = matches.count == (requireUniqueKey ? 2 : matchLimit);
            }];
            if (requireUniqueKey && matches.count > 1) { status = errSecParam; reason = @"ambiguous-key-reference"; break; }
            if (!partialRead && !matches.count && legacyRead && localPasswordRead && allowLegacyRead &&
                matchLimit == 1 && !hasPersistentSelector && !requestsSync && !attributes[KC(kSecAttrAccessGroup)] &&
                attributes[KC(kSecAttrAccount)] && (attributes[KC(kSecAttrService)] || attributes[KC(kSecAttrServer)])) {
                BOOL blockedQuery = NO;
                for (NSDictionary *filter in blocked) {
                    if (LCKeychainMatches(attributes, nil, filter, @{})) { blockedQuery = YES; break; }
                }
                NSDictionary *legacy = blockedQuery ? nil : legacyRead(attributes);
                NSMutableDictionary *candidate = nil;
                if (legacy) {
                    candidate = [NSMutableDictionary dictionary];
                    for (NSString *key in types) {
                        id value = legacy[key];
                        if (!value) continue;
                        if (([key isEqual:KC(kSecAttrIsInvisible)] || [key isEqual:KC(kSecAttrIsNegative)]) &&
                            [value isKindOfClass:NSNumber.class] && ([value isEqual:@0] || [value isEqual:@1])) {
                            value = @([value boolValue]);
                        }
                        candidate[key] = value;
                    }
                    candidate[KC(kSecClass)] = itemClass;
                    candidate[KC(kSecValueData)] = legacy[KC(kSecValueData)];
                    candidate[KC(kSecAttrCreationDate)] = legacy[KC(kSecAttrCreationDate)] ?: NSDate.date;
                    candidate[KC(kSecAttrModificationDate)] = legacy[KC(kSecAttrModificationDate)] ?: candidate[KC(kSecAttrCreationDate)];
                    if (!LCKeychainValidStore(@[candidate]) || !LCKeychainMatches(candidate, nil, attributes, defaults)) {
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
                    if (candidate) {
                        candidate[LCKeychainRecordRef] = LCKeychainNewRef(itemClass);
                        [matches addIndex:items.count];
                        [items addObject:candidate];
                        imported = candidate.copy;
                        dirty = YES;
                    }
                }
            }
            if (passwordItem && !requestsSync && !attributes[KC(kSecAttrAccessGroup)] &&
                (operation == LCKeychainDelete || (operation == LCKeychainUpdate && matches.count))) {
                if (operation == LCKeychainDelete && matchLimit == NSUIntegerMax && !localMetadataSelector &&
                    !hasPersistentSelector && ![legacyBlocked containsObject:attributes]) {
                    [legacyBlocked addObject:attributes.copy];
                    dirty = YES;
                }
                [matches enumerateIndexesUsingBlock:^(NSUInteger index, BOOL *stop) {
                    NSDictionary *item = items[index];
                    if (item[KC(kSecAttrAccessGroup)]) return;
                    NSMutableDictionary *filter = [@{KC(kSecClass): itemClass} mutableCopy];
                    for (NSString *key in LCKeychainPasswordDefaults(itemClass)) {
                        if (![key isEqual:KC(kSecAttrSynchronizable)]) filter[key] = item[key] ?: defaults[key];
                    }
                    if ([itemClass isEqual:KC(kSecClassGenericPassword)]) filter[KC(kSecAttrService)] = item[KC(kSecAttrService)] ?: @"";
                    if (![legacyBlocked containsObject:filter]) [legacyBlocked addObject:filter];
                }];
            }
            if (!matches.count) {
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
                NSDate *now = NSDate.date;
                [matches enumerateIndexesUsingBlock:^(NSUInteger index, BOOL *stop) {
                    NSMutableDictionary *item = [items[index] mutableCopy];
                    [item addEntriesFromDictionary:changes];
                    item[KC(kSecAttrModificationDate)] = now;
                    items[index] = item;
                }];
            }
        }
        if (!LCKeychainValidStore(items)) {
            status = errSecDuplicateItem; reason = @"duplicate-item"; break;
        }
        OSStatus writeStatus = LCKeychainWriteStore(store, items, legacyBlocked, splitStore, &reason);
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
    } while (0);
    close(lock);
    if (status != errSecSuccess) return fail(status, reason);
    if (imported) LCKeychainLogMessage(@"legacy-import", className, errSecSuccess, @"legacy-import-verified");
    if (result && output) *result = CFBridgingRetain(output);
    return status;
}

OSStatus LCManagedKeychainPerform(NSURL *directory, LCKeychainOperation operation,
                                  CFDictionaryRef input, CFDictionaryRef updates, CFTypeRef *result) {
    return LCKeychainPerform(directory, operation, input, updates, result, nil, nil);
}

OSStatus LCManagedKeychainPerformWithLegacyRead(NSURL *directory, LCKeychainOperation operation,
    CFDictionaryRef input, CFDictionaryRef updates, CFTypeRef *result, LCKeychainLegacyRead legacyRead) {
    return LCKeychainPerform(directory, operation, input, updates, result, nil, legacyRead);
}

static NSDictionary *LCKeychainGenerationRecord(NSDictionary *common, NSDictionary *specific, SecKeyRef key) {
    NSMutableDictionary *record = common.mutableCopy;
    if (specific) [record addEntriesFromDictionary:specific];
    if (![record[KC(kSecAttrIsPermanent)] boolValue]) return nil;
    [record removeObjectForKey:KC(kSecAttrIsPermanent)];
    record[KC(kSecClass)] = KC(kSecClassKey);
    record[KC(kSecValueRef)] = (__bridge id)key;
    return record;
}

static SecKeyRef LCManagedGenerateSoftwareKey(NSURL *directory, NSString *operation, CFDictionaryRef parameters,
                                               SecKeyRef *publicKey, CFErrorRef *error) CF_RETURNS_RETAINED {
    if (publicKey) *publicKey = NULL;
    if (error) *error = NULL;
    id input = (__bridge id)parameters;
    NSDictionary *options = [input isKindOfClass:NSDictionary.class] ? [input copy] : nil;
    NSDictionary *privateOptions = options[KC(kSecPrivateKeyAttrs)], *publicOptions = options[KC(kSecPublicKeyAttrs)];
    NSArray *locations = @[options ?: @{}, privateOptions ?: @{}, publicOptions ?: @{}];
    NSMutableArray *native = [NSMutableArray arrayWithCapacity:3], *stored = [NSMutableArray arrayWithCapacity:3];
    OSStatus status = options ? errSecSuccess : errSecParam;
    NSString *reason = @"invalid-key-parameters";
    BOOL softwareToken = options && LCKeychainTokenRequest(options);
    if (softwareToken) {
        for (id location in locations) {
            id token = [location isKindOfClass:NSDictionary.class] ? location[KC(kSecAttrTokenID)] : nil;
            if (token && (![token isKindOfClass:NSString.class] || ![token length])) {
                status = errSecParam; reason = @"invalid-token-id";
                break;
            }
        }
    }
    for (id location in locations) {
        if (status != errSecSuccess) break;
        if (![location isKindOfClass:NSDictionary.class]) { status = errSecParam; break; }
        NSMutableDictionary *crypto = [location mutableCopy], *record = [NSMutableDictionary dictionary];
        if (!native.count) {
            [crypto removeObjectForKey:KC(kSecPrivateKeyAttrs)];
            [crypto removeObjectForKey:KC(kSecPublicKeyAttrs)];
        }
        for (NSString *name in @[KC(kSecAttrIsPermanent), KC(kSecAttrApplicationTag), KC(kSecAttrLabel),
                                 KC(kSecAttrAccessible), KC(kSecAttrAccessGroup), KC(kSecAttrSynchronizable)]) {
            id value = crypto[name];
            if (!value) continue;
            if (softwareToken && [name isEqual:KC(kSecAttrAccessible)]) {
                [crypto removeObjectForKey:name];
                continue;
            }
            if (!LCKeychainValidAttribute(name, value, LCKeychainAttributeTypes(KC(kSecClassKey)), NO)) {
                status = errSecParam; reason = @"unsupported-key-storage-option"; break;
            }
            record[name] = value;
            [crypto removeObjectForKey:name];
        }
        if (softwareToken) {
            [crypto removeObjectForKey:KC(kSecAttrTokenID)];
            [crypto removeObjectForKey:KC(kSecAttrAccessControl)];
            [crypto removeObjectForKey:KC(kSecUseAuthenticationContext)];
        }
        for (NSString *name in LCKeychainKeyUsageAttributes()) {
            if (crypto[name]) record[name] = crypto[name];
        }
        [native addObject:crypto.copy];
        [stored addObject:record.copy];
    }
    if (status != errSecSuccess) {
        LCKeychainLogMessage(operation, @"key", status, LCKeychainFailureReason(reason, softwareToken));
        if (error) *error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, status, NULL);
        return NULL;
    }
    NSMutableDictionary *crypto = [native[0] mutableCopy];
    if (privateOptions) crypto[KC(kSecPrivateKeyAttrs)] = native[1];
    if (publicOptions) crypto[KC(kSecPublicKeyAttrs)] = native[2];
    SecKeyRef private = LCManagedCreateTemporaryKey(operation, NO, NULL, softwareToken, (__bridge CFDictionaryRef)crypto, error);
    if (!private) return NULL;

    // Mark keys at creation so callers can also persist them in a later SecItemAdd.
    objc_setAssociatedObject((__bridge id)private, &LCKeychainOwnedSoftwareKeyMarker, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    NSDictionary *privateRecord = LCKeychainGenerationRecord(stored[0], stored[1], private);
    id shouldStorePublic = stored[2][KC(kSecAttrIsPermanent)] ?: stored[0][KC(kSecAttrIsPermanent)];
    SecKeyRef public = (publicKey || [shouldStorePublic boolValue]) ? SecKeyCopyPublicKey(private) : NULL;
    if (public) objc_setAssociatedObject((__bridge id)public, &LCKeychainOwnedSoftwareKeyMarker, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    if ((publicKey || [shouldStorePublic boolValue]) && !public) {
        status = errSecInternalComponent; reason = @"temporary-public-key-unavailable";
    } else if (privateRecord || [shouldStorePublic boolValue]) {
        NSDictionary *publicRecord = public ? LCKeychainGenerationRecord(stored[0], stored[2], public) : nil;
        NSMutableDictionary *second = privateRecord && publicRecord ? publicRecord.mutableCopy : nil;
        if (second) {
            id reference = second[KC(kSecValueRef)];
            [second removeObjectForKey:KC(kSecValueRef)];
            status = LCKeychainPrepareKey(second, reference, NO, &reason);
            if (status != errSecSuccess) reason = LCKeychainFailureReason(reason, softwareToken);
        }
        if (status == errSecSuccess) {
            status = LCKeychainPerform(directory, LCKeychainAdd, (__bridge CFDictionaryRef)(privateRecord ?: publicRecord), NULL, NULL, second, nil);
            if (status != errSecSuccess) reason = softwareToken ? @"token-persistent-key-store-failed" : @"persistent-key-store-failed";
        }
    }
    if (status != errSecSuccess) {
        if (public) CFRelease(public);
        CFRelease(private);
        LCKeychainLogMessage(operation, @"key", status, reason);
        if (error) *error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, status, NULL);
        return NULL;
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
