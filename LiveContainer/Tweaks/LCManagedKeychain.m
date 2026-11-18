#import "LCManagedKeychain.h"
#import "LCDebugLog.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define KC(key) ((__bridge NSString *)key)
static const NSUInteger LCKeychainMaxBytes = 8 * 1024 * 1024;

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

static OSStatus LCValidateTemporaryKeyOptions(id input, BOOL allowKeyDictionaries, NSDictionary **validated, NSString **reason) {
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
                OSStatus status = LCValidateTemporaryKeyOptions(value, NO, &child, reason);
                if (status != errSecSuccess) return status;
                safe[key] = child;
                continue;
            }
            *reason = @"unsupported-key-attributes-dictionary";
        } else if ([key isEqual:KC(kSecAttrTokenID)]) {
            *reason = @"token-backed-key";
        } else if ([key isEqual:KC(kSecAttrAccessControl)] || [key isEqual:KC(kSecAttrAccessible)] ||
                   [key isEqual:KC(kSecUseAuthenticationContext)]) {
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

static SecKeyRef LCManagedCreateTemporaryKey(NSString *operation, BOOL import, CFDataRef data,
                                            CFDictionaryRef parameters, CFErrorRef *error) {
    if (error) *error = NULL;
    NSString *reason = nil;
    NSDictionary *validated = nil;
    OSStatus status;
    if (import && ![(__bridge id)data isKindOfClass:NSData.class]) {
        status = errSecParam;
        reason = @"invalid-key-data";
    } else {
        status = LCValidateTemporaryKeyOptions((__bridge id)parameters, !import, &validated, &reason);
    }
    if (status != errSecSuccess) {
        LCKeychainLogMessage(operation, @"key", status, reason);
        if (error) *error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, status, NULL);
        return NULL;
    }

    CFErrorRef systemError = NULL;
    CFDictionaryRef safeParameters = (__bridge CFDictionaryRef)validated;
    SecKeyRef key = import ? SecKeyCreateWithData(data, safeParameters, &systemError) :
        SecKeyCreateRandomKey(safeParameters, &systemError);
    if (!key) LCKeychainLogMessage(operation, @"key", LCKeyCreationErrorStatus(systemError), @"temporary-key-create-failed");
    if (error) *error = systemError;
    else if (systemError) CFRelease(systemError);
    return key;
}

SecKeyRef LCManagedCreateKeyWithData(CFDataRef data, CFDictionaryRef parameters, CFErrorRef *error) {
    return LCManagedCreateTemporaryKey(@"SecKeyCreateWithData", YES, data, parameters, error);
}

static BOOL LCKeychainValidAttribute(NSString *key, id value, NSDictionary *types, BOOL query) {
    Class expected = types[key];
    if (!expected || ![value isKindOfClass:expected]) return NO;
    if ([key isEqualToString:KC(kSecAttrSynchronizable)]) {
        return (LCKeychainIsBoolean(value) && ![value boolValue]) ||
            (query && [value isEqual:KC(kSecAttrSynchronizableAny)]);
    }
    if ([key isEqualToString:KC(kSecAttrAccessible)]) {
        return [value isEqual:KC(kSecAttrAccessibleWhenUnlocked)] || [value isEqual:KC(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)];
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

static NSString *LCKeychainSafeOption(NSString *key) {
    // Never echo arbitrary dictionary keys or attribute values into diagnostics.
    static NSArray<NSString *> *known;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        known = @[KC(kSecAttrAccessControl), KC(kSecAttrAccessible), KC(kSecAttrSynchronizable),
                  KC(kSecReturnRef), KC(kSecReturnPersistentRef), KC(kSecValueRef), KC(kSecValuePersistentRef),
                  KC(kSecUseAuthenticationContext), KC(kSecUseOperationPrompt), KC(kSecUseAuthenticationUI),
                  KC(kSecMatchItemList), KC(kSecUseItemList), KC(kSecMatchLimit)];
#pragma clang diagnostic pop
    });
    for (NSString *option in known) if ([option isEqual:key]) return [@"unsupported-option:" stringByAppendingString:option];
    return @"unsupported-or-invalid-option";
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
    return SecKeyCreateWithData((__bridge CFDataRef)item[KC(kSecValueData)], (__bridge CFDictionaryRef)parameters, NULL);
}

static OSStatus LCKeychainPrepareKey(NSMutableDictionary *record, id reference, BOOL identityImport) {
    if (reference && CFGetTypeID((__bridge CFTypeRef)reference) != SecKeyGetTypeID()) return errSecParam;
    SecKeyRef key = reference ? (__bridge SecKeyRef)reference : LCKeychainRestoreKey(record);
    if (!key) return errSecParam;
    NSDictionary *actual = CFBridgingRelease(SecKeyCopyAttributes(key));
    NSData *data = nil;
    // Memory-only PKCS#12 imports can still mark their software key as permanent.
    if (LCKeychainSoftwareKey(actual) && !actual[KC(kSecAttrTokenID)] && !actual[KC(kSecAttrAccessControl)] &&
        ![actual[KC(kSecAttrIsExtractable)] isEqual:@NO] &&
        (!reference || identityImport || ![actual[KC(kSecAttrIsPermanent)] boolValue])) {
        data = CFBridgingRelease(SecKeyCopyExternalRepresentation(key, NULL));
    }
    if (!reference) CFRelease(key);
    if (!data.length) return errSecUnimplemented;

    // Only persist policies that the reconstructed software key actually enforces.
    NSArray *intrinsic = [@[KC(kSecAttrKeyType), KC(kSecAttrKeyClass), KC(kSecAttrApplicationLabel),
        KC(kSecAttrKeySizeInBits), KC(kSecAttrEffectiveKeySize)] arrayByAddingObjectsFromArray:LCKeychainKeyUsageAttributes()];
    record[KC(kSecValueData)] = data;
    if (reference) {
        SecKeyRef restored = LCKeychainRestoreKey(@{KC(kSecValueData): data,
            KC(kSecAttrKeyType): actual[KC(kSecAttrKeyType)], KC(kSecAttrKeyClass): actual[KC(kSecAttrKeyClass)]});
        if (!restored) return errSecDecode;
        NSDictionary *restoredAttributes = CFBridgingRelease(SecKeyCopyAttributes(restored));
        CFRelease(restored);
        actual = restoredAttributes;
    }
    for (NSString *name in intrinsic) {
        if (record[name] && ![record[name] isEqual:actual[name]]) return errSecUnimplemented;
        if (actual[name]) record[name] = actual[name];
    }
    if (![record[KC(kSecAttrApplicationLabel)] isKindOfClass:NSData.class]) return errSecUnimplemented;
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

static id LCKeychainResult(NSDictionary *item, NSDictionary *privateKey, NSDictionary *defaults,
                           BOOL returnData, BOOL returnAttributes, BOOL returnRef) {
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
    if (!returnAttributes && !(returnRef && returnData)) return returnRef ? reference : (returnData ? item[KC(kSecValueData)] : nil);
    NSMutableDictionary *result = returnAttributes ? defaults.mutableCopy : [NSMutableDictionary dictionary];
    if (returnAttributes && privateKey) [result addEntriesFromDictionary:privateKey];
    if (returnAttributes) [result addEntriesFromDictionary:item];
    if (returnAttributes && privateKey) result[KC(kSecClass)] = KC(kSecClassIdentity);
    if (returnData) result[KC(kSecValueData)] = item[KC(kSecValueData)];
    if (returnRef) result[KC(kSecValueRef)] = reference;
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

static OSStatus LCKeychainPerform(NSURL *directory, LCKeychainOperation operation, CFDictionaryRef input,
                                  CFDictionaryRef updates, CFTypeRef *result, NSDictionary *additionalKey) {
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
    NSDictionary *types = [itemClass isKindOfClass:NSString.class] ? LCKeychainAttributeTypes(itemClass) : nil;
    NSString *className = types ? itemClass : @"unsupported";
    BOOL keyItem = [itemClass isEqual:KC(kSecClassKey)];
    BOOL identityItem = [itemClass isEqual:KC(kSecClassIdentity)];
    BOOL certificateItem = [itemClass isEqual:KC(kSecClassCertificate)] || identityItem;
    if (keyItem) className = @"key";
    if ([itemClass isEqual:KC(kSecClassCertificate)]) className = @"certificate";
    if ([itemClass isEqual:KC(kSecClassIdentity)]) className = @"identity";
    OSStatus (^fail)(OSStatus, NSString *) = ^OSStatus(OSStatus status, NSString *reason) {
        LCKeychainLogMessage(op, className, status, reason);
        return status;
    };
    if (!types) return fail(errSecParam, itemClass ? @"unsupported-class" : @"missing-class");

    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    attributes[KC(kSecClass)] = itemClass;
    BOOL returnData = NO, returnAttributes = NO, returnRef = NO;
    id valueReference = nil;
    NSDictionary *identityKey = nil;
    NSUInteger matchLimit = operation == LCKeychainCopy ? 1 : NSUIntegerMax;
    for (NSString *key in options) {
        if ([key isEqual:KC(kSecClass)]) continue;
        id value = options[key];
        if ([key isEqual:KC(kSecReturnData)] || [key isEqual:KC(kSecReturnAttributes)] ||
            [key isEqual:KC(kSecReturnRef)] || [key isEqual:KC(kSecReturnPersistentRef)]) {
            if ((operation != LCKeychainCopy && operation != LCKeychainAdd) || !LCKeychainIsBoolean(value)) return fail(errSecParam, LCKeychainSafeOption(key));
            if (![value boolValue]) continue;
            if ([key isEqual:KC(kSecReturnData)] && !identityItem) returnData = YES;
            else if ([key isEqual:KC(kSecReturnAttributes)]) returnAttributes = YES;
            else if ((keyItem || certificateItem) && [key isEqual:KC(kSecReturnRef)]) returnRef = YES;
            else return fail(errSecParam, LCKeychainSafeOption(key));
        } else if ([key isEqual:KC(kSecMatchLimit)]) {
            if (operation != LCKeychainCopy && operation != LCKeychainDelete) return fail(errSecParam, @"invalid-match-limit");
            if ([value isEqual:KC(kSecMatchLimitAll)]) matchLimit = NSUIntegerMax;
            else if ([value isEqual:KC(kSecMatchLimitOne)]) matchLimit = 1;
            else if ([value isKindOfClass:NSNumber.class] && !LCKeychainIsBoolean(value) &&
                     [value longLongValue] > 0 && [value isEqual:@([value longLongValue])]) {
                matchLimit = [value unsignedIntegerValue];
            } else return fail(errSecParam, @"unsupported-match-limit");
        } else if ((certificateItem || (keyItem && operation == LCKeychainAdd)) && [key isEqual:KC(kSecValueRef)]) {
            valueReference = value;
        } else if ((operation == LCKeychainAdd && [key isEqual:KC(kSecValueData)] && [value isKindOfClass:NSData.class]) ||
                   LCKeychainValidAttribute(key, value, types, operation != LCKeychainAdd)) {
            attributes[key] = value;
        } else {
            return fail(errSecParam, LCKeychainSafeOption(key));
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
                status = LCKeychainPrepareKey(record, private, YES);
                if (status != errSecSuccess || ![record[KC(kSecAttrKeyClass)] isEqual:KC(kSecAttrKeyClassPrivate)]) {
                    return fail(status ?: errSecParam, @"identity-key-not-exportable");
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
        OSStatus status = LCKeychainPrepareKey(attributes, valueReference, NO);
        if (status != errSecSuccess) return fail(status, @"key-not-supported-or-not-exportable");
    }
    NSDictionary *changes = (__bridge NSDictionary *)updates;
    if (operation == LCKeychainUpdate) {
        if (![changes isKindOfClass:NSDictionary.class] || !changes.count) return fail(errSecParam, @"invalid-update");
        for (NSString *key in changes) {
            id value = changes[key];
            if (certificateItem && ![key isEqual:KC(kSecAttrLabel)] && ![key isEqual:KC(kSecAttrAccessible)]) {
                return fail(errSecUnimplemented, @"unsupported-certificate-update");
            }
            if (keyItem && ![key isEqual:KC(kSecAttrLabel)] && ![key isEqual:KC(kSecAttrApplicationTag)] &&
                ![key isEqual:KC(kSecAttrAccessible)]) return fail(errSecUnimplemented, @"unsupported-key-update");
            if ([key isEqual:KC(kSecValueData)] && [value isKindOfClass:NSData.class]) continue;
            if ([key isEqual:KC(kSecAttrAccessGroup)] || !LCKeychainValidAttribute(key, value, types, NO)) return fail(errSecParam, LCKeychainSafeOption(key));
        }
    }
    if ([attributes[KC(kSecAttrSynchronizable)] isEqual:KC(kSecAttrSynchronizableAny)]) {
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
    do {
        NSURL *file = [directory URLByAppendingPathComponent:@"items-v1.plist"];
        NSMutableData *data = nil;
        int fd = open(file.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0 && errno != ENOENT) {
            status = errSecNotAvailable; reason = @"store-open"; break;
        }
        if (fd >= 0) {
            struct stat info;
            if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size > (off_t)LCKeychainMaxBytes) {
                close(fd);
                status = errSecDecode; reason = @"store-invalid-file"; break;
            }
            data = [NSMutableData dataWithLength:(NSUInteger)info.st_size];
            char *bytes = data.mutableBytes;
            NSUInteger offset = 0;
            while (offset < data.length) {
                ssize_t count = read(fd, bytes + offset, data.length - offset);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) break;
                offset += (NSUInteger)count;
            }
            close(fd);
            if (offset != data.length) { status = errSecNotAvailable; reason = @"store-read"; break; }
        }
        NSArray *existing = data ? [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil] : @[];
        if (!LCKeychainValidStore(existing)) {
            status = errSecDecode; reason = @"store-invalid-records"; break;
        }
        NSMutableArray *items = existing.mutableCopy;
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
                [items addObject:item];
            }
            if (result) output = LCKeychainResult(attributes, identityKey, defaults, returnData, returnAttributes, returnRef);
            if (result && returnRef && !output) { status = errSecDecode; reason = @"reference-restore-failed"; break; }
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
            [items enumerateObjectsUsingBlock:^(NSDictionary *item, NSUInteger index, BOOL *stop) {
                if (identityItem) {
                    if (![item[KC(kSecClass)] isEqual:KC(kSecClassCertificate)]) return;
                    NSArray *pair = LCKeychainIdentityPair(item, KC(kSecAttrPublicKeyHash));
                    NSDictionary *matchingKey = nil;
                    for (NSDictionary *key in pair ? privateKeys[pair] : nil) {
                        if (LCKeychainMatches(item, key, attributes, defaults)) { matchingKey = key; break; }
                    }
                    if (!matchingKey) return;
                    matchedKeys[@(index)] = matchingKey;
                } else if (!LCKeychainMatches(item, nil, attributes, defaults)) return;
                [matches addIndex:index];
                *stop = matches.count == matchLimit;
            }];
            if (!matches.count) { status = errSecItemNotFound; reason = @"item-not-found"; break; }
            if (operation == LCKeychainCopy) {
                if (result && (returnAttributes || returnData || returnRef)) {
                    NSMutableArray *results = [NSMutableArray arrayWithCapacity:matches.count];
                    [matches enumerateIndexesUsingBlock:^(NSUInteger index, BOOL *stop) {
                        id value = LCKeychainResult(items[index], matchedKeys[@(index)], defaults, returnData, returnAttributes, returnRef);
                        if (value) [results addObject:value];
                        else *stop = YES;
                    }];
                    if (results.count != matches.count) { status = errSecDecode; reason = @"reference-restore-failed"; break; }
                    output = matchLimit == 1 ? results.firstObject : results.copy;
                }
                break;
            }
            if (operation == LCKeychainDelete) {
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
        NSData *encoded = [NSPropertyListSerialization dataWithPropertyList:items format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
        if (!encoded || encoded.length > LCKeychainMaxBytes) {
            status = errSecAllocate; reason = @"store-size-or-encode"; break;
        }
        NSDataWritingOptions writeOptions = NSDataWritingAtomic;
#if TARGET_OS_IPHONE
        writeOptions |= NSDataWritingFileProtectionComplete;
#endif
        if (![encoded writeToURL:file options:writeOptions error:nil]) {
            status = errSecNotAvailable; reason = @"store-write"; break;
        }
    } while (0);
    close(lock);
    if (status != errSecSuccess) return fail(status, reason);
    if (result && output) *result = CFBridgingRetain(output);
    return status;
}

OSStatus LCManagedKeychainPerform(NSURL *directory, LCKeychainOperation operation,
                                  CFDictionaryRef input, CFDictionaryRef updates, CFTypeRef *result) {
    return LCKeychainPerform(directory, operation, input, updates, result, nil);
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
            if (!LCKeychainValidAttribute(name, value, LCKeychainAttributeTypes(KC(kSecClassKey)), NO)) {
                status = errSecParam; reason = @"unsupported-key-storage-option"; break;
            }
            record[name] = value;
            [crypto removeObjectForKey:name];
        }
        for (NSString *name in LCKeychainKeyUsageAttributes()) {
            if (crypto[name]) record[name] = crypto[name];
        }
        [native addObject:crypto.copy];
        [stored addObject:record.copy];
    }
    if (status != errSecSuccess) {
        LCKeychainLogMessage(operation, @"key", status, reason);
        if (error) *error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, status, NULL);
        return NULL;
    }
    NSMutableDictionary *crypto = [native[0] mutableCopy];
    if (privateOptions) crypto[KC(kSecPrivateKeyAttrs)] = native[1];
    if (publicOptions) crypto[KC(kSecPublicKeyAttrs)] = native[2];
    SecKeyRef private = LCManagedCreateTemporaryKey(operation, NO, NULL, (__bridge CFDictionaryRef)crypto, error);
    if (!private) return NULL;

    NSDictionary *privateRecord = LCKeychainGenerationRecord(stored[0], stored[1], private);
    id shouldStorePublic = stored[2][KC(kSecAttrIsPermanent)] ?: stored[0][KC(kSecAttrIsPermanent)];
    SecKeyRef public = (publicKey || [shouldStorePublic boolValue]) ? SecKeyCopyPublicKey(private) : NULL;
    if ((publicKey || [shouldStorePublic boolValue]) && !public) {
        status = errSecInternalComponent; reason = @"temporary-public-key-unavailable";
    } else if (privateRecord || [shouldStorePublic boolValue]) {
        NSDictionary *publicRecord = public ? LCKeychainGenerationRecord(stored[0], stored[2], public) : nil;
        NSMutableDictionary *second = privateRecord && publicRecord ? publicRecord.mutableCopy : nil;
        if (second) {
            id reference = second[KC(kSecValueRef)];
            [second removeObjectForKey:KC(kSecValueRef)];
            status = LCKeychainPrepareKey(second, reference, NO);
        }
        if (status == errSecSuccess) {
            status = LCKeychainPerform(directory, LCKeychainAdd, (__bridge CFDictionaryRef)(privateRecord ?: publicRecord), NULL, NULL, second);
        }
        reason = @"persistent-key-store-failed";
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
