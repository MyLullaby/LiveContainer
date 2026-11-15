@import UniformTypeIdentifiers;
#import "LCSharedUtils.h"
#import "UIKitPrivate.h"
#import "utils.h"
#import "FoundationPrivate.h"
#import "Tweaks.h"
#import "LCDebugLog.h"

@interface LCDocumentPickerHostHooks : NSObject
- (void)lc_setDocumentPickerHostIdentifier:(NSString *)identifier;
@end

static BOOL fixFilePicker;

void LCDocumentPickerHooksInit(void) {
    if(!NSUserDefaults.lcGuestAppId) return;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        fixFilePicker = [NSUserDefaults.guestAppInfo[@"doSymlinkInbox"] boolValue];
        BOOL fixHostIdentity = [NSUserDefaults.guestAppInfo[@"fixFilePickerNew"] boolValue] || NSUserDefaults.isSideStore;
        BOOL hostHookInstalled = NO;

        swizzle(UIDocumentPickerViewController.class, @selector(initForOpeningContentTypes:asCopy:), @selector(hook_initForOpeningContentTypes:asCopy:));
        swizzle(UIDocumentPickerViewController.class, @selector(initWithDocumentTypes:inMode:), @selector(hook_initWithDocumentTypes:inMode:));
        swizzle(UIDocumentBrowserViewController.class, @selector(initForOpeningContentTypes:), @selector(hook_initForOpeningContentTypes:));
        swizzleClassMethod(UTType.class, @selector(typeWithIdentifier:), @selector(hook_typeWithIdentifier:));
        if (fixFilePicker) {
            swizzle(NSURL.class, @selector(startAccessingSecurityScopedResource), @selector(hook_startAccessingSecurityScopedResource));
            swizzle(UIDocumentPickerViewController.class, @selector(setAllowsMultipleSelection:), @selector(hook_setAllowsMultipleSelection:));
        }
        if (fixHostIdentity) {
            // Resolve the private class at launch rather than binding it when LC loads.
            Class configurationClass = NSClassFromString(@"DOCConfiguration");
            Method original = class_getInstanceMethod(configurationClass, @selector(setHostIdentifier:));
            Method replacement = class_getInstanceMethod(LCDocumentPickerHostHooks.class, @selector(lc_setDocumentPickerHostIdentifier:));
            if (original && class_addMethod(configurationClass, @selector(lc_setDocumentPickerHostIdentifier:),
                                            method_getImplementation(replacement), method_getTypeEncoding(replacement))) {
                swizzle(configurationClass, @selector(setHostIdentifier:), @selector(lc_setDocumentPickerHostIdentifier:));
                hostHookInstalled = YES;
            }
        }
        LCDebugLog(@"DocumentPicker", @"core hooks installed inbox=%d hostFix=%d hostHookInstalled=%d",
                   fixFilePicker, fixHostIdentity, hostHookInstalled);
    });
}

@implementation UIDocumentPickerViewController(LiveContainerHook)

- (instancetype)hook_initForOpeningContentTypes:(NSArray<UTType *> *)contentTypes asCopy:(BOOL)asCopy {
    
    // prevent crash when selecting only folder
    BOOL shouldMultiselect = NO;
    if (fixFilePicker && [contentTypes count] == 1 && contentTypes[0] == UTTypeFolder) {
        shouldMultiselect = YES;
    }
    
    // if app is going to choose any unrecognized file type, then we replace it with @[UTTypeItem, UTTypeFolder];
    NSArray<UTType *> * contentTypesNew = @[UTTypeItem, UTTypeFolder];
    

    
    if(fixFilePicker) {
        UIDocumentPickerViewController* ans = [self hook_initForOpeningContentTypes:contentTypesNew asCopy:YES];
        if(shouldMultiselect) {
            [ans hook_setAllowsMultipleSelection:YES];
        }
        return ans;
    } else {
        return [self hook_initForOpeningContentTypes:contentTypesNew asCopy:asCopy];
    }
}

- (instancetype)hook_initWithDocumentTypes:(NSArray<UTType *> *)contentTypes inMode:(NSUInteger)mode {
    return [self initForOpeningContentTypes:contentTypes asCopy:(mode == 1 ? NO : YES)];
}

- (void)hook_setAllowsMultipleSelection:(BOOL)allowsMultipleSelection {
    if([self allowsMultipleSelection]) {
        return;
    }
    [self hook_setAllowsMultipleSelection:YES];
}

@end


@implementation UIDocumentBrowserViewController(LiveContainerHook)

- (instancetype)hook_initForOpeningContentTypes:(NSArray<UTType *> *)contentTypes {
    NSArray<UTType *> * contentTypesNew = @[UTTypeItem, UTTypeFolder];
    return [self hook_initForOpeningContentTypes:contentTypesNew];
}

@end


@implementation NSURL(LiveContainerHook)

- (BOOL)hook_startAccessingSecurityScopedResource {
    [self hook_startAccessingSecurityScopedResource];
    return YES;
}

@end

@implementation UTType(LiveContainerHook)

+(instancetype)hook_typeWithIdentifier:(NSString*)identifier {
    UTType* ans = [UTType hook_typeWithIdentifier:identifier];
    // imported / exported TypeWithIdentifier calls ___UTGetDeclarationStatusFromInfoPlist which directly creates types without tags from Info.plist
    if(ans) {
        return ans;
    } else if((ans = [UTType exportedTypeWithIdentifier:identifier])) {
        return ans;
    } else {
        return [UTType importedTypeWithIdentifier:identifier];
    }
}

@end


@implementation LCDocumentPickerHostHooks

- (void)lc_setDocumentPickerHostIdentifier:(NSString *)ignored {
    CFErrorRef error = NULL;
    void* taskSelf = SecTaskCreateFromSelf(NULL);
    CFTypeRef value = SecTaskCopyValueForEntitlement(taskSelf, CFSTR("application-identifier"), &error);
    CFRelease(taskSelf);
    if (value) {
        NSString *entStr = (__bridge NSString *)value;
        CFRelease(value);
        NSRange dotRange = [entStr rangeOfString:@"."];
        if (dotRange.location != NSNotFound) {
               NSString *result = [entStr substringFromIndex:dotRange.location + 1];
            [self lc_setDocumentPickerHostIdentifier:result];
        } else {
            [self lc_setDocumentPickerHostIdentifier:entStr];
        }
    } else if (error) {
        NSLog(@"Error fetching entitlement: %@", error);
        CFRelease(error);
        [self lc_setDocumentPickerHostIdentifier:ignored];
    }
}

@end
