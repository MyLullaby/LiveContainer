// SPDX-License-Identifier: GPL-3.0-only
// Dependency rewriting reuses IPAWorkshop's Mach-O editing workflow.
import Foundation

struct LCPluginPreparation {
    struct Manifest: Codable {
        let revision: Int
        let executable: String
        let injectedFiles: [String]
        let images: [String]
    }

    private static let stateDirectory = ".LCPluginPreparation"
    private static let manifestName = "LCPluginManifest.plist"

    static func manifest(in bundle: URL) throws -> Manifest? {
        let url = bundle.appendingPathComponent(manifestName)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try PropertyListDecoder().decode(Manifest.self, from: Data(contentsOf: url))
    }

    // Modify a disposable copy; only publish it after signing succeeds.
    static func stage(app: LCAppInfo, importing urls: [URL] = [], removing paths: [String] = [], inheriting oldApp: LCAppInfo? = nil) throws -> URL {
        let fm = FileManager.default
        let bundle = URL(fileURLWithPath: app.bundlePath()).resolvingSymlinksInPath()
        var inherited: [URL] = []
        if let oldApp {
            let oldBundle = URL(fileURLWithPath: oldApp.bundlePath()).resolvingSymlinksInPath()
            for path in try manifest(in: oldBundle)?.injectedFiles ?? [] {
                let file = try contained(path, in: oldBundle)
                let expected = (file.pathExtension.lowercased() == "bundle" ? "" : "Frameworks/") + file.lastPathComponent
                guard ["dylib", "framework", "bundle"].contains(file.pathExtension.lowercased()), path == expected else {
                    throw LCPluginError("旧应用的插件或资源缺失、路径无效：\(path)，已停止覆盖安装。")
                }
                // The incoming IPA owns conflicts; inherit only files it does not contain.
                if fm.fileExists(atPath: try contained(path, in: bundle).path) { continue }
                guard fm.fileExists(atPath: file.path) else {
                    throw LCPluginError("旧应用的插件或资源缺失：\(path)，已停止覆盖安装。")
                }
                inherited.append(file)
            }
        }
        guard !app.is32bit else { throw LCPluginError("直接注入插件暂不支持 32 位 Guest。") }
        if (!urls.isEmpty || !inherited.isEmpty) && (!app.dontInjectTweakLoader || !app.dontLoadTweakLoader) {
            throw LCPluginError("请先在应用设置中打开“不注入 TweakLoader”和“不加载 TweakLoader”。")
        }
        let info = try PropertyListSerialization.propertyList(from: Data(contentsOf: bundle.appendingPathComponent("Info.plist")), format: nil) as? [String: Any]
        guard let executable = info?["CFBundleExecutable"] as? String, !executable.isEmpty,
              executable == (executable as NSString).lastPathComponent else { throw LCPluginError("主程序文件名无效。") }
        let previous = try manifest(in: bundle)
        let inspection = try LCAppPlugins.inspect(app: app)
        let workspace = fm.temporaryDirectory.appendingPathComponent("LCPluginImport-\(UUID().uuidString)")
        try fm.createDirectory(at: workspace, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: workspace) }
        var items = inherited
        for (index, url) in urls.enumerated() {
            guard url.isFileURL, LCAppPlugins.extensions.contains(url.pathExtension.lowercased()), !url.lastPathComponent.hasPrefix(".") else {
                throw LCPluginError("请选择 dylib、deb 或 zip 插件文件。")
            }
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            let package = workspace.appendingPathComponent(String(index))
            if url.pathExtension.lowercased() == "dylib" {
                try fm.createDirectory(at: package, withIntermediateDirectories: true)
                try fm.copyItem(at: url, to: package.appendingPathComponent(url.lastPathComponent))
            } else { try LCUtils.extractPluginArchive(url.path, toPath: package.path) }
            let contents = try pluginItems(in: package, recursive: true)
            guard !contents.isEmpty else { throw LCPluginError("\(url.lastPathComponent) 内未找到可导入的库或资源。") }
            items += contents
        }
        var names = Set<String>()
        for item in items {
            guard names.insert(item.lastPathComponent.lowercased()).inserted else { throw LCPluginError("插件包包含重名文件：\(item.lastPathComponent)") }
            _ = try regularFiles(in: item)
        }
        let staged = bundle.deletingLastPathComponent().appendingPathComponent(".LCPlugin-\(UUID().uuidString)")
        do {
            try fm.copyItem(at: bundle, to: staged)
            // Legacy source copies and backups are never needed by this workflow.
            for name in [".LCPlugins", stateDirectory] {
                let old = staged.appendingPathComponent(name)
                if fm.fileExists(atPath: old.path) { try fm.removeItem(at: old) }
            }
            var injectedFiles = previous?.injectedFiles ?? []
            var images = previous?.images ?? []
            var removedLoads = Set<String>()
            if !paths.isEmpty {
                guard paths.allSatisfy({ path in
                    previous?.injectedFiles.contains(path) == true || inspection.images.contains { $0.id == path || $0.id.hasPrefix(path + "/") }
                }) else { throw LCPluginError("所选库不存在，请刷新列表。") }
                let removed = try paths.map { try contained($0, in: staged) }
                for reference in inspection.references where paths.contains(where: { reference.target == $0 || reference.target.hasPrefix($0 + "/") }) {
                    if reference.loader == executable {
                        removedLoads.insert(reference.load)
                    } else if !paths.contains(where: { reference.loader == $0 || reference.loader.hasPrefix($0 + "/") }) {
                        throw LCPluginError("\(reference.loader) 仍依赖 \(reference.target)，请先移除依赖它的插件。")
                    }
                }
                for file in removed where fm.fileExists(atPath: file.path) { try fm.removeItem(at: file) }
                injectedFiles.removeAll { path in paths.contains { path == $0 || path.hasPrefix($0 + "/") } }
                images.removeAll { image in paths.contains { image == $0 || image.hasPrefix($0 + "/") } }
            }
            let frameworks = staged.appendingPathComponent("Frameworks")
            try fm.createDirectory(at: frameworks, withIntermediateDirectories: true)
            var binaries: [URL] = []
            for item in items {
                let relative = (item.pathExtension.lowercased() == "bundle" ? "" : "Frameworks/") + item.lastPathComponent
                let destination = try contained(relative, in: staged)
                for reference in inspection.references where reference.loader == executable &&
                    (reference.target == relative || reference.target.hasPrefix(relative + "/")) {
                    removedLoads.insert(reference.load)
                }
                if fm.fileExists(atPath: destination.path) { try fm.removeItem(at: destination) }
                images.removeAll { $0 == relative || $0.hasPrefix(relative + "/") }
                try fm.copyItem(at: item, to: destination)
                if !injectedFiles.contains(relative) { injectedFiles.append(relative) }
                if item.pathExtension.lowercased() != "bundle" { binaries.append(try binaryURL(destination)) }
            }
            let aliases: Set<String> = ["CydiaSubstrate", "libsubstrate.dylib"]
            let needsRuntime = try binaries.contains { binary in
                try LCPluginMachO(url: binary).dependencies.contains { aliases.contains(($0 as NSString).lastPathComponent) }
            }
            let runtime = Bundle.main.bundleURL.appendingPathComponent("Frameworks/CydiaSubstrate.framework")
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
            let addedImages = binaries.map { String($0.path.dropFirst(staged.path.count + 1)) }
            images = Array(Set(images + addedImages)).sorted()
            let loads = addedImages.map { "@loader_path/" + $0 }
            try macho.edit(add: loads, remove: removedLoads)
            try macho.write(to: main)
            try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: main.path)
            guard Set(loads).isSubset(of: Set(try LCPluginMachO(url: main).dependencies)) else {
                throw LCPluginError("插件注入回读校验失败。")
            }
            let manifest = Manifest(revision: 3, executable: executable,
                                    injectedFiles: injectedFiles.sorted(), images: images)
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
            if name.hasPrefix(".") || name == "__MACOSX" || name.hasSuffix(".disabled") || name == "TweakLoader.dylib" { continue }
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

    static func binaryURL(_ url: URL) throws -> URL {
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
