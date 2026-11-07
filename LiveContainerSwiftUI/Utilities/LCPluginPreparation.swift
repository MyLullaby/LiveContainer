// SPDX-License-Identifier: GPL-3.0-only
// Dependency rewriting reuses IPAWorkshop's Mach-O editing workflow.
import Foundation
import CryptoKit

struct LCPluginPreparation {
    private struct Manifest: Codable {
        let revision: Int
        let fingerprint: String
        let executable: String
        let injectedFiles: [String]
        let images: [String]
    }

    private static let stateDirectory = ".LCPluginPreparation"
    private static let manifestName = "LCPluginManifest.plist"

    // Return a staged app only when the installed plugin configuration changed.
    static func stage(app: LCAppInfo) throws -> URL? {
        let fm = FileManager.default
        let bundle = URL(fileURLWithPath: app.bundlePath()).resolvingSymlinksInPath()
        let manifestURL = bundle.appendingPathComponent(manifestName)
        let previous = try fm.fileExists(atPath: manifestURL.path)
            ? PropertyListDecoder().decode(Manifest.self, from: Data(contentsOf: manifestURL)) : nil
        let root = app.isShared ? LCPath.lcGroupTweakPath : LCPath.tweakPath
        var items = try pluginItems(in: root, recursive: false)
        if let folder = app.tweakFolder, !folder.isEmpty {
            guard folder == (folder as NSString).lastPathComponent, folder != ".", folder != ".." else {
                throw LCPluginError("插件目录名称无效。")
            }
            let selected = root.appendingPathComponent(folder)
            if fm.fileExists(atPath: selected.path) {
                items += try pluginItems(in: selected, recursive: true)
            }
        }
        guard !items.isEmpty || previous != nil else { return nil }
        guard app.dontInjectTweakLoader && app.dontLoadTweakLoader else {
            // Explicitly enabled legacy loading continues to use the original loader.
            guard let previous else { return nil }
            if previous.injectedFiles.isEmpty && previous.images.isEmpty { return nil }
            throw LCPluginError("此应用已使用直接注入插件，请先移除插件并启动一次，再启用旧版 TweakLoader。")
        }
        guard !app.is32bit else { throw LCPluginError("直接注入插件暂不支持 32 位 Guest。") }
        var names = Set<String>()
        for item in items {
            guard names.insert(item.lastPathComponent.lowercased()).inserted else {
                throw LCPluginError("插件文件重名：\(item.lastPathComponent)")
            }
        }
        let bundleInfo = try PropertyListSerialization.propertyList(from: Data(contentsOf: bundle.appendingPathComponent("Info.plist")), format: nil) as? [String: Any]
        guard let executable = bundleInfo?["CFBundleExecutable"] as? String,
              !executable.isEmpty, executable == (executable as NSString).lastPathComponent else {
            throw LCPluginError("Guest 缺少有效的主程序文件名。")
        }
        var hash = SHA256()
        for item in items.sorted(by: { $0.path < $1.path }) {
            hash.update(data: Data(item.path.utf8))
            for file in try regularFiles(in: item) {
                hash.update(data: Data(file.path.utf8))
                hash.update(data: try Data(contentsOf: file, options: .mappedIfSafe))
            }
        }
        // Rebuild when the bundled Substrate compatibility runtime changes too.
        let runtime = Bundle.main.bundleURL.appendingPathComponent("Frameworks/CydiaSubstrate.framework")
        for file in try regularFiles(in: runtime) {
            hash.update(data: try Data(contentsOf: file, options: .mappedIfSafe))
        }
        let fingerprint = hash.finalize().map { String(format: "%02x", $0) }.joined()
        if previous?.revision == 1, previous?.fingerprint == fingerprint,
           previous?.executable == executable { return nil }

        let staged = bundle.deletingLastPathComponent().appendingPathComponent(".LCPlugin-\(UUID().uuidString)")
        do {
            try fm.copyItem(at: bundle, to: staged)
            let backup = staged.appendingPathComponent(stateDirectory)
            if let previous {
                guard previous.executable == executable else {
                    throw LCPluginError("插件备份与当前主程序不一致，请覆盖安装原始 IPA。")
                }
                for path in previous.injectedFiles {
                    let file = try contained(path, in: staged)
                    if fm.fileExists(atPath: file.path) { try fm.removeItem(at: file) }
                }
                let original = backup.appendingPathComponent("Executable")
                guard fm.fileExists(atPath: original.path) else {
                    throw LCPluginError("插件原始主程序备份缺失，请覆盖安装原始 IPA。")
                }
                try fm.removeItem(at: staged.appendingPathComponent(executable))
                try fm.copyItem(at: original, to: staged.appendingPathComponent(executable))
            } else {
                guard !fm.fileExists(atPath: backup.path) else {
                    throw LCPluginError("插件备份目录冲突，请覆盖安装原始 IPA。")
                }
                try fm.createDirectory(at: backup, withIntermediateDirectories: true)
                try fm.copyItem(at: staged.appendingPathComponent(executable), to: backup.appendingPathComponent("Executable"))
            }

            let frameworks = staged.appendingPathComponent("Frameworks")
            try fm.createDirectory(at: frameworks, withIntermediateDirectories: true)
            var injectedFiles: [String] = []
            var binaries: [URL] = []
            for item in items {
                let relative = (item.pathExtension.lowercased() == "bundle" ? "" : "Frameworks/") + item.lastPathComponent
                let destination = try contained(relative, in: staged)
                guard !fm.fileExists(atPath: destination.path) else {
                    throw LCPluginError("插件与原应用文件冲突：\(relative)")
                }
                try fm.copyItem(at: item, to: destination)
                injectedFiles.append(relative)
                if item.pathExtension.lowercased() != "bundle" { binaries.append(try binaryURL(destination)) }
            }
            let aliases: Set<String> = ["CydiaSubstrate", "libsubstrate.dylib"]
            let needsRuntime = try binaries.contains { binary in
                try LCPluginMachO(url: binary).dependencies.contains { aliases.contains(($0 as NSString).lastPathComponent) }
            }
            let embeddedRuntime = frameworks.appendingPathComponent("CydiaSubstrate.framework")
            if needsRuntime, !fm.fileExists(atPath: embeddedRuntime.path) {
                try fm.copyItem(at: runtime, to: embeddedRuntime)
                injectedFiles.append("Frameworks/CydiaSubstrate.framework")
                binaries.insert(try binaryURL(embeddedRuntime), at: 0)
            }
            let available = try pluginItems(in: frameworks, recursive: true)
                .filter { $0.pathExtension.lowercased() != "bundle" }.map { try binaryURL($0) }
            let byName = Dictionary(grouping: available, by: \.lastPathComponent)
            for binary in binaries {
                var macho = try LCPluginMachO(url: binary)
                try macho.requireARM64()
                try macho.requireDecrypted()
                let searchPaths = try macho.runtimeSearchPaths
                var replacements: [String: String] = [:]
                for dependency in try macho.dependencies {
                    let name = (dependency as NSString).lastPathComponent
                    if dependency.hasPrefix("/System/Library/") || (dependency.hasPrefix("/usr/lib/") && !aliases.contains(name)) { continue }
                    if dependency.hasPrefix("@rpath/libswift"), searchPaths.contains("/usr/lib/swift") { continue }
                    let matches = aliases.contains(name) && fm.fileExists(atPath: embeddedRuntime.path)
                        ? [try binaryURL(embeddedRuntime)] : byName[name] ?? []
                    let target: URL
                    if matches.count == 1 {
                        target = matches[0]
                    } else if matches.isEmpty, fm.fileExists(atPath: staged.appendingPathComponent(name).path) {
                        target = staged.appendingPathComponent(name)
                    } else {
                        throw LCPluginError("\(binary.lastPathComponent) 的依赖\(matches.isEmpty ? "缺失" : "存在重名")：\(dependency)")
                    }
                    replacements[dependency] = "@loader_path/" + relativePath(from: binary.deletingLastPathComponent(), to: target)
                }
                try macho.edit(replacements: replacements)
                try macho.write(to: binary)
                try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binary.path)
            }
            let main = staged.appendingPathComponent(executable)
            var macho = try LCPluginMachO(url: main)
            try macho.requireARM64()
            try macho.requireDecrypted()
            let images = binaries.map { String($0.path.dropFirst(staged.path.count + 1)) }
            let loads = images.map { "@loader_path/" + $0 }
            try macho.edit(add: loads)
            try macho.write(to: main)
            try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: main.path)
            guard Set(loads).isSubset(of: Set(try LCPluginMachO(url: main).dependencies)) else {
                throw LCPluginError("插件注入回读校验失败。")
            }
            let manifest = Manifest(revision: 1, fingerprint: fingerprint, executable: executable,
                                    injectedFiles: injectedFiles, images: images)
            try PropertyListEncoder().encode(manifest).write(to: staged.appendingPathComponent(manifestName), options: .atomic)
            return staged
        } catch {
            try? fm.removeItem(at: staged)
            throw error
        }
    }

    static func commit(staged: URL, to bundle: URL) throws {
        // Preserve the old app until signing and the final replacement both succeed.
        _ = try FileManager.default.replaceItemAt(bundle, withItemAt: staged, backupItemName: nil, options: [])
    }

    static func pluginItems(in root: URL, recursive: Bool) throws -> [URL] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: root.path) else { return [] }
        var result: [URL] = []
        for item in try fm.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isSymbolicLinkKey, .isDirectoryKey]).sorted(by: { $0.path < $1.path }) {
            let name = item.lastPathComponent
            if name.hasPrefix(".") || name.hasSuffix(".disabled") || name == "TweakLoader.dylib" { continue }
            let values = try item.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
            guard values.isSymbolicLink != true else { continue }
            if ["dylib", "framework", "bundle"].contains(item.pathExtension.lowercased()) {
                result.append(item)
            } else if recursive, values.isDirectory == true {
                result += try pluginItems(in: item, recursive: true)
            }
        }
        return result
    }

    private static func regularFiles(in root: URL) throws -> [URL] {
        let values = try root.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey])
        guard values.isSymbolicLink != true else { throw LCPluginError("插件包内含符号链接：\(root.lastPathComponent)") }
        if values.isRegularFile == true { return [root] }
        guard values.isDirectory == true else { throw LCPluginError("不支持的插件文件：\(root.lastPathComponent)") }
        return try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
            .sorted(by: { $0.path < $1.path }).flatMap { try regularFiles(in: $0) }
    }

    private static func contained(_ relative: String, in root: URL) throws -> URL {
        let url = root.appendingPathComponent(relative).standardizedFileURL
        guard !relative.hasPrefix("/"), url.path.hasPrefix(root.standardizedFileURL.path + "/"),
              url.resolvingSymlinksInPath().path.hasPrefix(root.resolvingSymlinksInPath().path + "/") else {
            throw LCPluginError("插件路径越界：\(relative)")
        }
        return url
    }

    private static func binaryURL(_ url: URL) throws -> URL {
        guard url.pathExtension.lowercased() == "framework" else { return url }
        let data = try Data(contentsOf: url.appendingPathComponent("Info.plist"))
        let info = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        guard let name = info?["CFBundleExecutable"] as? String, !name.isEmpty,
              name == (name as NSString).lastPathComponent, name != ".", name != ".." else {
            throw LCPluginError("Framework 缺少有效的 CFBundleExecutable：\(url.lastPathComponent)")
        }
        return try contained(name, in: url)
    }

    private static func relativePath(from: URL, to: URL) -> String {
        let a = from.resolvingSymlinksInPath().standardizedFileURL.pathComponents
        let b = to.resolvingSymlinksInPath().standardizedFileURL.pathComponents
        var common = 0
        while common < min(a.count, b.count), a[common] == b[common] { common += 1 }
        return (Array(repeating: "..", count: a.count - common) + b.dropFirst(common)).joined(separator: "/")
    }
}
