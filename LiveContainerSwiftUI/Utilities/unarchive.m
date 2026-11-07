#import "unarchive.h"

#include "archive.h"
#include "archive_entry.h"

static int
copy_data(struct archive *ar, struct archive *aw, NSProgress *progress)
{
  int r;
  const void *buff;
  size_t size;
  la_int64_t offset;

  for (;;) {
    r = archive_read_data_block(ar, &buff, &size, &offset);
    if (r == ARCHIVE_EOF)
      return (ARCHIVE_OK);
    if (r < ARCHIVE_OK)
      return (r);
    r = archive_write_data_block(aw, buff, size, offset);
    if (r < ARCHIVE_OK) {
      fprintf(stderr, "%s\n", archive_error_string(aw));
      return (r);
    }
    progress.completedUnitCount += size;
  }
}

int extract(NSString* fileToExtract, NSString* extractionPath, NSProgress* progress)
{
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int flags;
    int r;

    /* Select which attributes we want to restore. */
    flags = ARCHIVE_EXTRACT_TIME;
    flags |= ARCHIVE_EXTRACT_PERM;
    flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;

    // Calculate decompressed size
    a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    if ((r = archive_read_open_filename(a, fileToExtract.fileSystemRepresentation, 10240))) {
        archive_read_free(a);
        return 1;
    }
    while ((r = archive_read_next_header(a, &entry)) != ARCHIVE_EOF) {
        if (r < ARCHIVE_OK)
            fprintf(stderr, "%s\n", archive_error_string(a));
        if (r < ARCHIVE_WARN) {
            archive_read_close(a);
            archive_read_free(a);
            return 1;
        }
        progress.totalUnitCount += archive_entry_size(entry);
    }
    archive_read_close(a);
    archive_read_free(a);

    // Re-open the archive and extract
    a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    if ((r = archive_read_open_filename(a, fileToExtract.fileSystemRepresentation, 10240))) {
        archive_read_free(a);
        return 1;
    }
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    while ((r = archive_read_next_header(a, &entry)) != ARCHIVE_EOF) {
        if (r == ARCHIVE_EOF)
            break;
        if (r < ARCHIVE_OK)
            fprintf(stderr, "%s\n", archive_error_string(a));
        if (r < ARCHIVE_WARN)
            break;
        
        NSString* currentFile = [NSString stringWithUTF8String:archive_entry_pathname(entry)];
        NSString* fullOutputPath = [extractionPath stringByAppendingPathComponent:currentFile];
        //printf("extracting %@ to %@\n", currentFile, fullOutputPath);
        archive_entry_set_pathname(entry, fullOutputPath.fileSystemRepresentation);
        
        r = archive_write_header(ext, entry);
        if (r < ARCHIVE_OK)
            fprintf(stderr, "%s\n", archive_error_string(ext));
        else if (archive_entry_size(entry) > 0) {
            r = copy_data(a, ext, progress);
            if (r < ARCHIVE_OK)
                fprintf(stderr, "%s\n", archive_error_string(ext));
            if (r < ARCHIVE_WARN)
                break;
        }
        r = archive_write_finish_entry(ext);
        if (r < ARCHIVE_OK)
            fprintf(stderr, "%s\n", archive_error_string(ext));
        if (r < ARCHIVE_WARN)
            break;
    }
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    
    return 0;
}

#import "LCUtils.h"

static BOOL extractPluginData(struct archive *reader, NSString *destination, BOOL deb, NSError **error) {
    struct archive_entry *entry;
    uint64_t total = 0;
    NSUInteger count = 0;
    BOOL foundPayload = NO;
    int status;
    while ((status = archive_read_next_header(reader, &entry)) == ARCHIVE_OK) {
        const char *raw = archive_entry_pathname(entry);
        NSString *name = raw ? [NSString stringWithUTF8String:raw] : nil;
        la_int64_t size = archive_entry_size(entry);
        if (!name || size < 0 || size > 512 * 1024 * 1024 || ++count > 200000) break;
        total += size;
        if (total > 1024ULL * 1024 * 1024) break;
        if (deb) {
            if (![name isEqualToString:@"data.tar"] && ![name hasPrefix:@"data.tar."]) continue;
            if (foundPayload) break;
            foundPayload = YES;
            NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)size];
            NSUInteger offset = 0;
            while (offset < data.length) {
                la_ssize_t read = archive_read_data(reader, (char *)data.mutableBytes + offset, data.length - offset);
                if (read <= 0) break;
                offset += read;
            }
            if (offset != data.length) break;
            struct archive *payload = archive_read_new();
            archive_read_support_format_tar(payload);
            archive_read_support_filter_all(payload);
            BOOL success = archive_read_open_memory(payload, data.bytes, data.length) == ARCHIVE_OK
                && extractPluginData(payload, destination, NO, error);
            archive_read_free(payload);
            if (!success) return NO;
            continue;
        }
        mode_t type = archive_entry_filetype(entry);
        if (archive_entry_symlink(entry) || archive_entry_hardlink(entry)) continue;
        if (type != AE_IFREG && type != AE_IFDIR) continue;
        NSString *path = [destination stringByAppendingPathComponent:name].stringByStandardizingPath;
        if ([name hasPrefix:@"/"] || ![path hasPrefix:[destination stringByAppendingString:@"/"]]) {
            if ([path isEqualToString:destination] && type == AE_IFDIR) continue;
            break;
        }
        NSFileManager *fm = NSFileManager.defaultManager;
        if (type == AE_IFDIR) {
            if (![fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:error]) return NO;
            continue;
        }
        if ([fm fileExistsAtPath:path]) break;
        if (![fm createDirectoryAtPath:path.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:error]) return NO;
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)size];
        NSUInteger offset = 0;
        while (offset < data.length) {
            la_ssize_t read = archive_read_data(reader, (char *)data.mutableBytes + offset, data.length - offset);
            if (read <= 0) break;
            offset += read;
        }
        if (offset != data.length) break;
        if (![data writeToFile:path options:NSDataWritingAtomic error:error]) return NO;
    }
    if (status == ARCHIVE_EOF && (!deb || foundPayload)) return YES;
    if (error && !*error) {
        const char *detail = archive_error_string(reader);
        *error = [NSError errorWithDomain:@"LCPluginImport" code:1 userInfo:@{
            NSLocalizedDescriptionKey: detail ? @(detail) : @"插件包损坏、路径无效、超过解压限制或缺少 data.tar。"
        }];
    }
    return NO;
}

@implementation LCUtils (PluginImport)
+ (BOOL)extractPluginArchive:(NSString *)path toPath:(NSString *)destination error:(NSError **)error {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *staged = [destination.stringByDeletingLastPathComponent stringByAppendingPathComponent:[@".LCPluginImport-" stringByAppendingString:NSUUID.UUID.UUIDString]];
    if (![fm createDirectoryAtPath:staged withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    struct archive *reader = archive_read_new();
    BOOL deb = [path.pathExtension.lowercaseString isEqualToString:@"deb"];
    if (deb) archive_read_support_format_ar(reader);
    else archive_read_support_format_zip(reader);
    archive_read_support_filter_all(reader);
    BOOL success = archive_read_open_filename(reader, path.fileSystemRepresentation, 10240) == ARCHIVE_OK
        && extractPluginData(reader, staged, deb, error);
    if (!success && error && !*error) {
        const char *detail = archive_error_string(reader);
        *error = [NSError errorWithDomain:@"LCPluginImport" code:2 userInfo:@{NSLocalizedDescriptionKey: detail ? @(detail) : @"无法解压插件包。"}];
    }
    archive_read_free(reader);
    if (success) success = [fm moveItemAtPath:staged toPath:destination error:error];
    [fm removeItemAtPath:staged error:nil];
    return success;
}
@end
