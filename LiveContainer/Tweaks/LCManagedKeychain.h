#import <Foundation/Foundation.h>
#import <Security/Security.h>

typedef NS_ENUM(NSUInteger, LCKeychainOperation) {
    LCKeychainAdd, LCKeychainCopy, LCKeychainUpdate, LCKeychainDelete,
};

OSStatus LCManagedKeychainPerform(NSURL *directory, LCKeychainOperation operation,
                                  CFDictionaryRef input, CFDictionaryRef updates, CFTypeRef *result);

SecKeyRef LCManagedCreateRandomKey(NSURL *directory, CFDictionaryRef parameters, CFErrorRef *error) CF_RETURNS_RETAINED;
SecKeyRef LCManagedCreateKeyWithData(CFDataRef data, CFDictionaryRef parameters, CFErrorRef *error) CF_RETURNS_RETAINED;
OSStatus LCManagedGenerateKeyPair(NSURL *directory, CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey);
