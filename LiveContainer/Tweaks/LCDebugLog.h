#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
@interface LCDebugLog : NSObject
+ (BOOL)isEnabled;
+ (BOOL)setLoggingEnabled:(BOOL)enabled;
+ (NSString *)readLogs;
+ (BOOL)clearLogs;
+ (void)recordMessage:(NSString *)message category:(NSString *)category NS_SWIFT_NAME(record(_:category:));
@end

void LCDebugLogMessage(NSString *category, NSString *format, ...) NS_FORMAT_FUNCTION(2, 3);
// Gate arguments as well as writes so disabled diagnostics do no extra work.
#define LCDebugLog(category, ...) do { if ([LCDebugLog isEnabled]) LCDebugLogMessage(category, __VA_ARGS__); } while (0)
NS_ASSUME_NONNULL_END
