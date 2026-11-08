#import <Foundation/Foundation.h>

@interface LCGuestURLRouter : NSObject
+ (BOOL)canRouteURL:(NSURL *)url;
+ (NSDictionary<NSString *, id> *)requestForURL:(NSURL *)url NS_SWIFT_NAME(request(for:));
+ (NSString *)diagnosticsForBundleName:(NSString *)bundleName NS_SWIFT_NAME(diagnostics(forBundleName:));
@end

void LCGuestURLRouterInit(void);
