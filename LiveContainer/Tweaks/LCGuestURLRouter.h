#import <Foundation/Foundation.h>

@interface LCGuestURLRouter : NSObject
+ (BOOL)canRouteURL:(NSURL *)url;
+ (NSDictionary<NSString *, id> *)requestForURL:(NSURL *)url NS_SWIFT_NAME(request(for:));
@end

void LCGuestURLRouterInit(void);
