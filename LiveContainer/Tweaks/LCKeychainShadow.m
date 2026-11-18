// Password matching and result shaping adapted from unixzii/SimRun:
// f8557b3d22cb9f023e7eb3ade9f362eed76df014, src/sim/shims/app/keychain/keychain.m.
//
// MIT License
// Copyright (c) 2026 Cyandev
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#import "LCKeychainShadow.h"
#import "LCDebugLog.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
#import <TargetConditionals.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

static const NSUInteger LCShadowMaxBytes = 8 * 1024 * 1024;

// Deliberately narrow: unsupported Security objects never enter the serializer.
static BOOL LCShadowAttributesValid(NSDictionary *attributes) {
    static NSSet *keys;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keys = [NSSet setWithArray:@[@"acct", @"svce", @"agrp", @"sync", @"pdmn", @"cdat", @"mdat",
                                    @"labl", @"desc", @"icmt", @"crtr", @"type", @"invi", @"nega",
                                    @"gena", @"sdmn", @"srvr", @"ptcl", @"atyp", @"port", @"path", @"alis"]];
    });
    if (![attributes isKindOfClass:NSDictionary.class]) return NO;
    for (id key in attributes) {
        id value = attributes[key];
        if (![keys containsObject:key] ||
            !([value isKindOfClass:NSString.class] || [value isKindOfClass:NSNumber.class] ||
              [value isKindOfClass:NSData.class] || [value isKindOfClass:NSDate.class])) return NO;
        if ([key isEqual:@"sync"] && ![value isKindOfClass:NSNumber.class] &&
            ![value isEqual:(id)kSecAttrSynchronizableAny]) return NO;
    }
    return YES;
}

static NSDictionary *LCShadowAttributes(NSDictionary *query) {
    NSMutableDictionary *attributes = query.mutableCopy;
    [attributes removeObjectsForKeys:@[@"class", @"v_Data", @"r_Data", @"r_Attributes", @"r_Ref",
                                       @"r_PersistentRef", @"m_Limit"]];
    return attributes;
}

static BOOL LCShadowSupported(NSDictionary *query, BOOL update) {
    if (![query isKindOfClass:NSDictionary.class]) return NO;
    if (update) {
        NSMutableDictionary *attributes = query.mutableCopy;
        id data = attributes[@"v_Data"];
        [attributes removeObjectForKey:@"v_Data"];
        return (!data || [data isKindOfClass:NSData.class]) && LCShadowAttributesValid(attributes);
    }
    if (![@[@"genp", @"inet"] containsObject:query[@"class"] ?: @""]) return NO;
    for (NSString *key in @[@"r_Data", @"r_Attributes", @"r_Ref", @"r_PersistentRef"]) {
        if (query[key] && ![query[key] isKindOfClass:NSNumber.class]) return NO;
    }
    if ([query[@"r_Ref"] boolValue] || [query[@"r_PersistentRef"] boolValue]) return NO;
    id limit = query[@"m_Limit"];
    if (limit && ![limit isEqual:@"m_LimitOne"] && ![limit isEqual:@"m_LimitAll"] &&
        !([limit isKindOfClass:NSNumber.class] && [limit integerValue] > 0)) return NO;
    id data = query[@"v_Data"];
    if (data && ![data isKindOfClass:NSData.class]) return NO;
    return LCShadowAttributesValid(LCShadowAttributes(query));
}

static id LCShadowNormalize(id value) {
    if (([value isKindOfClass:NSString.class] || [value isKindOfClass:NSData.class]) && ![value length]) return nil;
    return value;
}

static BOOL LCShadowEqual(id a, id b) {
    a = LCShadowNormalize(a);
    b = LCShadowNormalize(b);
    if (!a || !b) return a == b;
    if ([a isEqual:b]) return YES;
    if ([a isKindOfClass:NSNumber.class] && [b isKindOfClass:NSString.class]) return [[a stringValue] isEqual:b];
    if ([b isKindOfClass:NSNumber.class] && [a isKindOfClass:NSString.class]) return [a isEqual:[b stringValue]];
    return NO;
}

static NSArray *LCShadowPrimaryKeys(NSString *itemClass) {
    return [itemClass isEqual:@"genp"] ? @[@"acct", @"svce", @"agrp", @"sync"] :
        @[@"acct", @"sdmn", @"srvr", @"ptcl", @"atyp", @"port", @"path", @"agrp", @"sync"];
}

static BOOL LCShadowSameIdentity(NSDictionary *a, NSDictionary *b) {
    if (![a[@"class"] isEqual:b[@"class"]]) return NO;
    for (NSString *key in LCShadowPrimaryKeys(a[@"class"])) {
        if (!LCShadowEqual(a[@"attributes"][key], b[@"attributes"][key])) return NO;
    }
    return YES;
}

static NSUInteger LCShadowLimit(NSDictionary *query) {
    id limit = query[@"m_Limit"];
    if ([limit isEqual:@"m_LimitAll"]) return NSUIntegerMax;
    return [limit isKindOfClass:NSNumber.class] ? [limit unsignedIntegerValue] : 1;
}

static NSArray *LCShadowFind(NSArray *items, NSDictionary *query, BOOL *unknown) {
    NSMutableArray *found = NSMutableArray.new;
    NSDictionary *attributes = LCShadowAttributes(query);
    for (NSDictionary *item in items) {
        if (![item[@"class"] isEqual:query[@"class"]]) continue;
        NSDictionary *stored = item[@"attributes"];
        BOOL matches = YES;
        for (NSString *key in attributes) {
            if ([key isEqual:@"sync"]) continue;
            if (!stored[key] && ![item[@"complete"] boolValue] &&
                ![LCShadowPrimaryKeys(item[@"class"]) containsObject:key]) {
                *unknown = YES;
                matches = NO;
                break;
            }
            if (!LCShadowEqual(stored[key], attributes[key])) { matches = NO; break; }
        }
        id sync = query[@"sync"];
        if (![sync isEqual:(id)kSecAttrSynchronizableAny] && [sync boolValue] != [stored[@"sync"] boolValue]) matches = NO;
        if (matches) [found addObject:item];
    }
    return found;
}

static id LCShadowResult(NSDictionary *item, NSDictionary *query, BOOL *unknown) {
    BOOL data = [query[@"r_Data"] boolValue], attributes = [query[@"r_Attributes"] boolValue];
    if (data && !item[@"value"]) *unknown = YES;
    if (attributes && ![item[@"complete"] boolValue]) *unknown = YES;
    if (!data && !attributes) return nil;
    if (!attributes) return item[@"value"];
    NSMutableDictionary *result = [item[@"attributes"] mutableCopy];
    result[@"class"] = item[@"class"];
    if (data && item[@"value"]) result[@"v_Data"] = item[@"value"];
    return result;
}

@interface LCKeychainShadow ()
@property NSString *directory;
@property NSString *accessGroup;
@property BOOL paused;
@end

@implementation LCKeychainShadow
- (instancetype)initWithHome:(NSString *)home accessGroup:(NSString *)accessGroup {
    if ((self = [super init])) {
        _directory = [home stringByAppendingPathComponent:@"Library/LCKeychainShadow"];
        _accessGroup = accessGroup;
        LCDebugLog(@"KeychainShadow", @"enabled mode=shadow backend=passwords");
    }
    return self;
}

- (void)recordUnsupportedOperation:(NSString *)operation {
    LCDebugLog(@"KeychainShadow", @"op=%@ verdict=unsupported", operation);
}

- (BOOL)writeData:(NSData *)data name:(NSString *)name {
    NSDataWritingOptions options = NSDataWritingAtomic;
#if TARGET_OS_IOS
    options |= NSDataWritingFileProtectionComplete;
#endif
    return [data writeToFile:[self.directory stringByAppendingPathComponent:name] options:options error:nil];
}

- (NSData *)key {
    NSString *path = [self.directory stringByAppendingPathComponent:@"store.key"];
    if ([NSFileManager.defaultManager fileExistsAtPath:path]) {
        NSData *key = [NSData dataWithContentsOfFile:path];
        return key.length == 64 ? key : nil;
    }
    // Never replace a missing key when ciphertext already exists.
    if ([NSFileManager.defaultManager fileExistsAtPath:[self.directory stringByAppendingPathComponent:@"store.bin"]]) return nil;
    NSMutableData *key = [NSMutableData dataWithLength:64];
    if (SecRandomCopyBytes(kSecRandomDefault, key.length, key.mutableBytes) != errSecSuccess ||
        ![self writeData:key name:@"store.key"]) return nil;
    return key;
}

- (NSData *)crypt:(NSData *)data key:(NSData *)key iv:(NSData *)iv encrypt:(BOOL)encrypt {
    NSMutableData *output = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
    size_t length = 0;
    if (CCCrypt(encrypt ? kCCEncrypt : kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                key.bytes, kCCKeySizeAES256, iv.bytes, data.bytes, data.length,
                output.mutableBytes, output.length, &length) != kCCSuccess) return nil;
    output.length = length;
    return output;
}

- (NSData *)mac:(NSData *)data key:(NSData *)key {
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, (const char *)key.bytes + 32, 32, data.bytes, data.length, bytes);
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

- (NSMutableDictionary *)loadWithKey:(NSData *)key {
    NSString *path = [self.directory stringByAppendingPathComponent:@"store.bin"];
    if (![NSFileManager.defaultManager fileExistsAtPath:path]) {
        return [@{@"version": @1, @"items": NSMutableArray.new, @"coverage": NSMutableArray.new} mutableCopy];
    }
    NSNumber *size = [NSFileManager.defaultManager attributesOfItemAtPath:path error:nil][NSFileSize];
    if (!size || size.unsignedLongLongValue > LCShadowMaxBytes) return nil;
    NSData *sealed = [NSData dataWithContentsOfFile:path];
    if (sealed.length < 64) return nil;
    NSData *body = [sealed subdataWithRange:NSMakeRange(0, sealed.length - 32)];
    NSData *tag = [self mac:body key:key];
    const unsigned char *expected = tag.bytes, *actual = (const unsigned char *)sealed.bytes + body.length;
    unsigned char difference = 0;
    for (NSUInteger i = 0; i < tag.length; i++) difference |= expected[i] ^ actual[i];
    if (difference) return nil;
    NSData *plain = [self crypt:[body subdataWithRange:NSMakeRange(16, body.length - 16)] key:key
                             iv:[body subdataWithRange:NSMakeRange(0, 16)] encrypt:NO];
    id root = plain ? [NSPropertyListSerialization propertyListWithData:plain options:NSPropertyListMutableContainers
                                                               format:NULL error:nil] : nil;
    if (![root isKindOfClass:NSDictionary.class] || ![root[@"version"] isEqual:@1] ||
        ![root[@"items"] isKindOfClass:NSArray.class] || ![root[@"coverage"] isKindOfClass:NSArray.class]) return nil;
    for (id item in root[@"items"]) {
        if (![item isKindOfClass:NSDictionary.class] ||
            ![@[@"genp", @"inet"] containsObject:item[@"class"] ?: @""] ||
            !LCShadowAttributesValid(item[@"attributes"]) || ![item[@"complete"] isKindOfClass:NSNumber.class] ||
            (item[@"value"] && ![item[@"value"] isKindOfClass:NSData.class])) return nil;
    }
    for (id signature in root[@"coverage"]) if (![signature isKindOfClass:NSData.class]) return nil;
    if (root[@"epoch"] && ![root[@"epoch"] isKindOfClass:NSData.class]) return nil;
    return root;
}

- (BOOL)save:(NSMutableDictionary *)store key:(NSData *)key {
    if ([store[@"items"] count] > 1024 || [store[@"coverage"] count] > 512) {
        [store[@"items"] removeAllObjects];
        [store[@"coverage"] removeAllObjects];
        LCDebugLog(@"KeychainShadow", @"verdict=capacity-reset");
    }
    NSData *plain = [NSPropertyListSerialization dataWithPropertyList:store format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    if (!plain || plain.length > LCShadowMaxBytes - 64) return NO;
    NSMutableData *iv = [NSMutableData dataWithLength:16];
    if (SecRandomCopyBytes(kSecRandomDefault, iv.length, iv.mutableBytes) != errSecSuccess) return NO;
    NSData *cipher = [self crypt:plain key:key iv:iv encrypt:YES];
    if (!cipher) return NO;
    NSMutableData *sealed = iv.mutableCopy;
    [sealed appendData:cipher];
    [sealed appendData:[self mac:sealed key:key]];
    return [self writeData:sealed name:@"store.bin"];
}

- (NSData *)signature:(NSDictionary *)query wantsResult:(BOOL)wantsResult key:(NSData *)key {
    NSMutableArray *pairs = [NSMutableArray arrayWithObject:@(wantsResult)];
    for (NSString *name in [query.allKeys sortedArrayUsingSelector:@selector(compare:)]) [pairs addObject:@[name, query[name]]];
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:pairs format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    return data ? [self mac:data key:key] : nil;
}

// Import only what the original call revealed; no extra system reads or prompts.
- (NSUInteger)learnQuery:(NSDictionary *)query result:(id)result items:(NSMutableArray *)items {
    if (!result) return 0;
    BOOL attributes = [query[@"r_Attributes"] boolValue], data = [query[@"r_Data"] boolValue];
    NSArray *results = LCShadowLimit(query) == 1 ? @[result] : ([result isKindOfClass:NSArray.class] ? result : nil);
    if (!results) return 0;
    NSMutableArray *observed = NSMutableArray.new;
    for (id entry in results) {
        NSMutableDictionary *stored;
        NSData *value;
        if (attributes) {
            if (![entry isKindOfClass:NSDictionary.class]) continue;
            stored = [entry mutableCopy];
            value = data ? stored[@"v_Data"] : nil;
            [stored removeObjectsForKeys:@[@"class", @"v_Data"]];
            if (!LCShadowAttributesValid(stored) || (value && ![value isKindOfClass:NSData.class])) continue;
        } else {
            if (!data || ![entry isKindOfClass:NSData.class] || LCShadowLimit(query) != 1) continue;
            stored = [LCShadowAttributes(query) mutableCopy];
            BOOL identityKnown = YES;
            for (NSString *name in LCShadowPrimaryKeys(query[@"class"])) {
                if (![name isEqual:@"sync"] && !stored[name]) identityKnown = NO;
            }
            if (!identityKnown || [stored[@"sync"] isEqual:(id)kSecAttrSynchronizableAny]) continue;
            value = entry;
        }
        if (!stored[@"agrp"]) stored[@"agrp"] = self.accessGroup;
        if (!stored[@"sync"]) stored[@"sync"] = @NO;
        NSMutableDictionary *item = [@{@"class": query[@"class"], @"attributes": stored, @"complete": @(attributes)} mutableCopy];
        if (value) item[@"value"] = value;
        NSUInteger index = [items indexOfObjectPassingTest:^BOOL(NSDictionary *old, NSUInteger idx, BOOL *stop) {
            return LCShadowSameIdentity(old, item);
        }];
        if (index == NSNotFound) {
            [items addObject:item];
        } else {
            NSDictionary *old = items[index];
            if (!value && old[@"value"]) item[@"value"] = old[@"value"];
            // An attributes-only read may have followed an external password update.
            if (!value && ![old[@"attributes"][@"mdat"] isEqual:stored[@"mdat"]]) [item removeObjectForKey:@"value"];
            if (!attributes && [old[@"complete"] boolValue]) {
                item[@"attributes"] = old[@"attributes"];
                item[@"complete"] = @YES;
            }
            items[index] = item;
        }
        [observed addObject:item];
    }
    if (attributes && LCShadowLimit(query) == NSUIntegerMax && observed.count == results.count) {
        BOOL unknown = NO;
        NSArray *matches = LCShadowFind(items, query, &unknown);
        for (NSDictionary *item in matches) {
            if (![observed containsObject:item]) [items removeObjectIdenticalTo:item];
        }
    }
    return observed.count;
}

- (void)mirrorWrite:(NSString *)operation query:(NSDictionary *)query updates:(NSDictionary *)updates items:(NSMutableArray *)items {
    BOOL unknown = NO;
    NSArray *found = LCShadowFind(items, query, &unknown);
    if (unknown && ![operation isEqual:@"add"]) {
        // A successful write may affect rows whose filter attributes weren't observed.
        [items removeAllObjects];
        return;
    }
    if ([operation isEqual:@"delete"]) {
        [items removeObjectsInArray:found];
    } else if ([operation isEqual:@"add"]) {
        NSMutableDictionary *attributes = [LCShadowAttributes(query) mutableCopy];
        if (!attributes[@"sync"]) attributes[@"sync"] = @NO;
        NSMutableDictionary *item = [@{@"class": query[@"class"], @"attributes": attributes, @"complete": @NO,
                                      @"value": query[@"v_Data"] ?: NSData.data} mutableCopy];
        NSIndexSet *duplicates = [items indexesOfObjectsPassingTest:^BOOL(NSDictionary *old, NSUInteger idx, BOOL *stop) {
            return LCShadowSameIdentity(old, item);
        }];
        [items removeObjectsAtIndexes:duplicates];
        [items addObject:item];
    } else {
        for (NSMutableDictionary *item in found) {
            NSMutableDictionary *attributes = [item[@"attributes"] mutableCopy];
            [attributes addEntriesFromDictionary:LCShadowAttributes(updates)];
            item[@"attributes"] = attributes;
            item[@"complete"] = @NO; // modification time and other system defaults aren't observable here
            if (updates[@"v_Data"]) item[@"value"] = updates[@"v_Data"];
        }
    }
}

- (OSStatus)performOperation:(NSString *)operation query:(NSDictionary *)query updates:(NSDictionary *)updates
                      result:(CFTypeRef *)result call:(OSStatus (^)(BOOL *))call {
    BOOL fallback = NO;
    if (![LCDebugLog isEnabled]) {
        self.paused = YES;
        return call(&fallback);
    }
    BOOL read = [operation isEqual:@"copy"];
    BOOL supported = LCShadowSupported(query, NO) && (!updates || LCShadowSupported(updates, YES));
    // Matching on value data or synchronizable-any writes needs separate semantics.
    if ((![operation isEqual:@"add"] && query[@"v_Data"]) || (!read && [query[@"sync"] isEqual:(id)kSecAttrSynchronizableAny] &&
                                      ![operation isEqual:@"delete"] && ![operation isEqual:@"update"]) ||
        [updates[@"sync"] isEqual:(id)kSecAttrSynchronizableAny]) supported = NO;
    NSDictionary *directoryAttributes = @{NSFilePosixPermissions: @0700};
#if TARGET_OS_IOS
    directoryAttributes = @{NSFilePosixPermissions: @0700, NSFileProtectionKey: NSFileProtectionComplete};
#endif
    if (![NSFileManager.defaultManager createDirectoryAtPath:self.directory withIntermediateDirectories:YES
                                                attributes:directoryAttributes error:nil]) {
        self.paused = YES;
        LCDebugLog(@"KeychainShadow", @"op=%@ verdict=storage-unavailable", operation);
        return call(&fallback);
    }
    int fd = open([self.directory stringByAppendingPathComponent:@"store.lock"].fileSystemRepresentation,
                  O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    // Never wait behind another diagnostic transaction or a system authentication prompt.
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0) {
        self.paused = YES;
        if (fd >= 0) close(fd);
        [self writeData:[NSUUID.UUID.UUIDString dataUsingEncoding:NSUTF8StringEncoding] name:@"epoch"];
        OSStatus status = call(&fallback);
        [self writeData:[NSUUID.UUID.UUIDString dataUsingEncoding:NSUTF8StringEncoding] name:@"epoch"];
        LCDebugLog(@"KeychainShadow", @"op=%@ verdict=skipped-concurrent system=%d", operation, (int)status);
        return status;
    }
    NSData *key = [self key];
    NSMutableDictionary *store = key ? [self loadWithKey:key] : nil;
    if (!store) {
        self.paused = YES;
        close(fd);
        LCDebugLog(@"KeychainShadow", @"op=%@ verdict=storage-unavailable", operation);
        return call(&fallback);
    }
    NSString *epochPath = [self.directory stringByAppendingPathComponent:@"epoch"];
    NSData *previousEpoch = [NSData dataWithContentsOfFile:epochPath];
    if (self.paused || (store[@"epoch"] && ![store[@"epoch"] isEqual:previousEpoch])) {
        [store[@"items"] removeAllObjects];
        [store[@"coverage"] removeAllObjects];
    }
    self.paused = NO;
    NSData *epoch = [NSUUID.UUID.UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    if (![self writeData:epoch name:@"epoch"]) {
        self.paused = YES;
        close(fd);
        LCDebugLog(@"KeychainShadow", @"op=%@ verdict=storage-unavailable", operation);
        return call(&fallback);
    }
    NSMutableArray *items = store[@"items"], *coverage = store[@"coverage"];
    NSData *signature = supported ? [self signature:query wantsResult:result != NULL key:key] : nil;
    BOOL unknown = NO;
    NSArray *found = supported ? LCShadowFind(items, query, &unknown) : @[];
    OSStatus local = found.count ? errSecSuccess : errSecItemNotFound;
    NSMutableArray *values = NSMutableArray.new;
    if (supported && read && result) {
        NSUInteger limit = LCShadowLimit(query);
        for (NSUInteger i = 0; i < MIN(found.count, limit); i++) {
            id value = LCShadowResult(found[i], query, &unknown);
            if (value) [values addObject:value];
        }
    }
    BOOL wantsOutput = supported && ([query[@"r_Data"] boolValue] || [query[@"r_Attributes"] boolValue]);
    id expected = LCShadowLimit(query) == 1 ? values.firstObject : (wantsOutput ? values : nil);
    // Evaluate before the real call and before importing the new observation.
    OSStatus status = call(&fallback);
    BOOL concurrent = ![[NSData dataWithContentsOfFile:epochPath] isEqual:epoch];
    id actual = supported && read && !fallback && !concurrent && wantsOutput &&
        status == errSecSuccess && result ? (__bridge id)*result : nil;
    NSString *verdict;
    NSUInteger learned = 0;
    if (concurrent || fallback || !supported) {
        verdict = concurrent ? @"skipped-concurrent" : (fallback ? @"unsupported-fallback" : @"unsupported");
        if (concurrent || !read) {
            [items removeAllObjects];
            [coverage removeAllObjects];
        }
    } else if (read) {
        BOOL covered = signature && [coverage containsObject:signature];
        BOOL singleIdentified = found.count == 1 && LCShadowLimit(query) == 1;
        for (NSString *name in LCShadowPrimaryKeys(query[@"class"])) {
            if (![name isEqual:@"sync"] && !query[name]) singleIdentified = NO;
        }
        if ((covered || singleIdentified) && !unknown &&
            (status == errSecSuccess || status == errSecItemNotFound)) {
            BOOL sameResult = expected == actual || [expected isEqual:actual];
            if (LCShadowLimit(query) == NSUIntegerMax &&
                [expected isKindOfClass:NSArray.class] && [actual isKindOfClass:NSArray.class]) {
                // Match-all has no ordering contract; compare multiplicities, not array order.
                NSCountedSet *left = [[NSCountedSet alloc] initWithArray:expected];
                NSCountedSet *right = [[NSCountedSet alloc] initWithArray:actual];
                sameResult = [expected count] == [actual count];
                for (id value in left) {
                    if ([left countForObject:value] != [right countForObject:value]) sameResult = NO;
                }
            }
            BOOL equal = local == status && (!result || !wantsOutput || status != errSecSuccess || sameResult);
            verdict = equal ? @"match" : @"mismatch";
        } else {
            verdict = (status == errSecSuccess || status == errSecItemNotFound) ? @"unseeded" : @"system-error";
        }
        if (status == errSecSuccess) {
            learned = [self learnQuery:query result:actual items:items];
        } else if (status == errSecItemNotFound) {
            [items removeObjectsInArray:found];
        }
        BOOL completeSnapshot = [query[@"r_Attributes"] boolValue] && LCShadowLimit(query) == NSUIntegerMax &&
            [actual isKindOfClass:NSArray.class] && learned > 0 && learned == [actual count];
        // A data-only or limited multi-result read can't establish complete coverage.
        if (signature && (status == errSecSuccess || status == errSecItemNotFound)) [coverage removeObject:signature];
        if (signature && (status == errSecItemNotFound || (learned && singleIdentified) || completeSnapshot)) {
            if (![coverage containsObject:signature]) [coverage addObject:signature];
        }
    } else {
        verdict = @"write-observed";
        [coverage removeAllObjects];
        if (status == errSecSuccess) [self mirrorWrite:operation query:query updates:updates items:items];
    }
    // Keep our own epoch: a bypass racing with save must invalidate the next load.
    store[@"epoch"] = epoch;
    BOOL saved = [self save:store key:key];
    if (!saved) self.paused = YES;
    close(fd);
    NSString *itemClass = [query[@"class"] isEqual:@"genp"] ? @"genp" : ([query[@"class"] isEqual:@"inet"] ? @"inet" : @"other");
    NSString *queryID = signature ? [[signature base64EncodedStringWithOptions:0] substringToIndex:12] : @"unsupported";
    if (read) {
        LCDebugLog(@"KeychainShadow", @"op=%@ class=%@ query=%@ verdict=%@ local=%d system=%d localCount=%lu imported=%lu saved=%d",
                   operation, itemClass, queryID, verdict, (int)local, (int)status, (unsigned long)found.count, (unsigned long)learned, saved);
    } else {
        LCDebugLog(@"KeychainShadow", @"op=%@ class=%@ query=%@ verdict=%@ system=%d localCount=%lu saved=%d",
                   operation, itemClass, queryID, verdict, (int)status, (unsigned long)found.count, saved);
    }
    return status;
}
@end
