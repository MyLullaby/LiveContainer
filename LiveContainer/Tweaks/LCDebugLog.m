#import "LCDebugLog.h"
#import "LCSharedUtils.h"
#import "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static const off_t LCMaxDebugBytes = 4 * 1024 * 1024;

static NSURL *LCDebugDirectory(void) {
    return [[LCSharedUtils appGroupPath] URLByAppendingPathComponent:@"LiveContainer/DebugLogs" isDirectory:YES];
}

static NSURL *LCDebugEnabledFile(void) {
    return [LCDebugDirectory() URLByAppendingPathComponent:@"enabled"];
}

static int LCOpenDebugLog(NSString *filename) {
    NSURL *directory = LCDebugDirectory();
    if (!directory || ![NSFileManager.defaultManager createDirectoryAtURL:directory withIntermediateDirectories:YES attributes:nil error:nil]) return -1;
    int fd = open([directory URLByAppendingPathComponent:filename].fileSystemRepresentation, O_CREAT | O_RDWR | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0 && flock(fd, LOCK_EX) != 0) { close(fd); return -1; }
    return fd;
}

static BOOL LCWriteDebugData(int fd, NSData *data) {
    const char *bytes = data.bytes;
    NSUInteger remaining = data.length;
    while (remaining) {
        ssize_t count = write(fd, bytes, remaining);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return NO;
        bytes += count;
        remaining -= count;
    }
    return YES;
}

static NSString *LCReadLogs(NSString *filename) {
    int fd = LCOpenDebugLog(filename);
    if (fd < 0) return @"无法读取共享 Debug 日志。";
    struct stat info;
    NSMutableData *data = [NSMutableData new];
    if (fstat(fd, &info) == 0) {
        data.length = (NSUInteger)MIN(info.st_size, LCMaxDebugBytes);
        NSUInteger offset = 0;
        while (offset < data.length) {
            ssize_t count = pread(fd, (char *)data.mutableBytes + offset, data.length - offset, offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { data.length = offset; break; }
            offset += count;
        }
    }
    close(fd);
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"日志内容无法读取，请清空后重新复现。";
}

static BOOL LCClearLogs(NSString *filename) {
    int fd = LCOpenDebugLog(filename);
    if (fd < 0) return NO;
    BOOL success = ftruncate(fd, 0) == 0;
    close(fd);
    return success;
}

static void LCAppendLog(NSString *filename, NSString *category, NSString *message, BOOL requiresDebug) {
    if (message.length > 8192) message = [[message substringWithRange:[message rangeOfComposedCharacterSequencesForRange:NSMakeRange(0, 8192)]] stringByAppendingString:@"…[truncated]"];
    NSString *line = [NSString stringWithFormat:@"%@ [%@] host=%@ guest=%@ pid=%d %@\n", NSDate.date, category,
        NSUserDefaults.lcAppUrlScheme ?: @"unknown", NSUserDefaults.lcGuestAppId ?: @"library", getpid(), message];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    int fd = LCOpenDebugLog(filename);
    if (fd < 0) {
        if (!requiresDebug) NSLog(@"%@", line);
        return;
    }
    // Serialize append, trim, clear and mode changes across LC hosts and LiveProcess.
    if (!requiresDebug || [LCDebugLog isEnabled]) {
        struct stat info;
        if (fstat(fd, &info) == 0 && info.st_size + data.length > LCMaxDebugBytes) {
            NSMutableData *tail = [NSMutableData dataWithLength:LCMaxDebugBytes / 2];
            ssize_t count;
            do { count = pread(fd, tail.mutableBytes, tail.length, MAX(0, info.st_size - (off_t)tail.length)); } while (count < 0 && errno == EINTR);
            if (count <= 0 || ftruncate(fd, 0) != 0) { close(fd); return; }
            tail.length = count;
            const char *bytes = tail.bytes;
            NSUInteger start = 0;
            while (start < tail.length && bytes[start++] != '\n') {}
            LCWriteDebugData(fd, [tail subdataWithRange:NSMakeRange(start, tail.length - start)]);
        }
        if (!LCWriteDebugData(fd, data) && !requiresDebug) NSLog(@"%@", line);
    }
    close(fd);
}

@implementation LCDebugLog
+ (BOOL)isEnabled {
    NSURL *file = LCDebugEnabledFile();
    return file && access(file.fileSystemRepresentation, F_OK) == 0;
}

+ (BOOL)setLoggingEnabled:(BOOL)enabled {
    int fd = LCOpenDebugLog(@"debug.log");
    if (fd < 0) return NO;
    NSURL *file = LCDebugEnabledFile();
    BOOL success = enabled ? [NSData.data writeToURL:file options:NSDataWritingAtomic error:nil] :
        (unlink(file.fileSystemRepresentation) == 0 || errno == ENOENT);
    close(fd);
    if (success && enabled) LCDebugLog(@"Debug", @"enabled build=%@ iOS=%@", NSUserDefaults.lcMainBundle.infoDictionary[@"LCVersionInfo"] ?: @"unknown", NSProcessInfo.processInfo.operatingSystemVersionString);
    return success;
}

+ (NSString *)readLogs { return LCReadLogs(@"debug.log"); }
+ (BOOL)clearLogs { return LCClearLogs(@"debug.log"); }
+ (NSString *)readKeychainLogs { return LCReadLogs(@"keychain.log"); }
+ (BOOL)clearKeychainLogs { return LCClearLogs(@"keychain.log"); }

+ (void)recordMessage:(NSString *)message category:(NSString *)category {
    LCDebugLog(category, @"%@", message);
}
@end

void LCDebugLogMessage(NSString *category, NSString *format, ...) {
    if (![LCDebugLog isEnabled]) return;
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    LCAppendLog(@"debug.log", category, message, YES);
}

void LCKeychainLogMessage(NSString *operation, NSString *itemClass, int status, NSString *reason) {
    LCAppendLog(@"keychain.log", @"LCKeychain",
                [NSString stringWithFormat:@"op=%@ class=%@ status=%d reason=%@", operation, itemClass, status, reason], NO);
}
