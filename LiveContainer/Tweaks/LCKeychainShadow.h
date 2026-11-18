#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

// Diagnostic backend only. The block must always return the real system result.
@interface LCKeychainShadow : NSObject
- (instancetype)initWithHome:(NSString *)home accessGroup:(NSString *)accessGroup;
- (OSStatus)performOperation:(NSString *)operation
                       query:(NSDictionary *)query
                     updates:(nullable NSDictionary *)updates
                      result:(CFTypeRef _Nullable * _Nullable)result
                        call:(OSStatus (^)(BOOL *fallback))call;
- (void)recordUnsupportedOperation:(NSString *)operation;
@end

NS_ASSUME_NONNULL_END
