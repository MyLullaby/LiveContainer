@import Foundation;

// Outcome of handling a return-to-library URL for this LiveContainer instance.
// The caller (LCTabView, which owns the UI) decides what to do with it: a
// restart is only required when a guest app currently occupies this process.
typedef NS_ENUM(NSInteger, LCReturnToLibraryResult) {
    // Not addressed to this instance; handle the URL normally.
    LCReturnToLibraryResultNotHandled = 0,
    // Already on the library interface: reveal the app list without restarting.
    LCReturnToLibraryResultShowAppList,
    // A guest app is running: relaunch this instance back to the app list.
    LCReturnToLibraryResultRestart,
};

@interface LCSharedUtils : NSObject
+ (NSString*) teamIdentifier;
+ (NSString *)appGroupID;
+ (NSURL*) appGroupPath;
+ (NSString *)certificatePassword;
+ (BOOL)launchToGuestAppWithClassicMode:(NSUInteger)classicMode;
+ (BOOL)launchToGuestAppWithURL:(NSURL *)url;
+ (BOOL)isReturnToLibraryURL:(NSURL *)url;
+ (LCReturnToLibraryResult)handleReturnToLibraryURL:(NSURL *)url NS_SWIFT_NAME(handleReturnToLibraryURL(_:));
+ (void)setWebPageUrlForNextLaunch:(NSString*)urlString;
+ (BOOL)isLCSchemeInUse:(NSString*)lc;
+ (NSString*)getContainerUsingLCSchemeWithFolderName:(NSString*)folderName;
+ (void)setContainerUsingByLC:(NSString*)lc folderName:(NSString*)folderName auditToken:(uint64_t)val57;
+ (void)moveSharedAppFolderBack;
+ (NSBundle*)findBundleWithBundleId:(NSString*)bundleId isSharedAppOut:(bool*)isSharedAppOut;
+ (void)dumpPreferenceToPath:(NSString*)plistLocationTo dataUUID:(NSString*)dataUUID;
+ (NSString*)findDefaultContainerWithBundleId:(NSString*)bundleId;
+ (NSArray<NSString*>*)lcUnorderedUrlSchemes;
+ (NSArray<NSString*>*)lcUrlSchemes;
@end
