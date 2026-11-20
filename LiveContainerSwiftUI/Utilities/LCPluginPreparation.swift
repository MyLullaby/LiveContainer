// SPDX-License-Identifier: GPL-3.0-only
// Dependency rewriting reuses IPAWorkshop's Mach-O editing workflow.
import Foundation

struct LCPluginPreparation {
    enum LoadPath: String, Codable, CaseIterable {
        case rpath, executable, loader
    }

    struct Options: Codable {
        var loadPath: LoadPath = .executable
        var installAtRoot = false
        var weak = true
        var includeExtensions = false
        var replaceSubstrateWithElleKit = false
    }

    struct Manifest: Codable {
        let revision: Int
        let executable: String
        let injectedFiles: [String]
        let images: [String]
        let options: Options?
    }

    private static let stateDirectory = ".LCPluginPreparation"
    private static let manifestName = "LCPluginManifest.plist"

    static func manifest(in bundle: URL) throws -> Manifest? {
        let url = bundle.appendingPathComponent(manifestName)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try PropertyListDecoder().decode(Manifest.self, from: Data(contentsOf: url))
    }

    // Modify a disposable copy; only publish it after signing succeeds.
    static func stage(app: LCAppInfo, importing urls: [URL] = [], removing paths: [String] = [], inheriting oldApp: LCAppInfo? = nil, options requestedOptions: Options? = nil) throws -> URL {
        let fm = FileManager.default
        let bundle = URL(fileURLWithPath: app.bundlePath()).resolvingSymlinksInPath()
        let previous = try manifest(in: bundle)
        var options = requestedOptions ?? previous?.options ?? Options()
        var items: [(url: URL, path: String)] = []
        if let oldApp {
            let oldBundle = URL(fileURLWithPath: oldApp.bundlePath()).resolvingSymlinksInPath()
            let oldManifest = try manifest(in: oldBundle)
            if requestedOptions == nil, let oldManifest {
                options = oldManifest.options ?? Options(loadPath: .loader, weak: false)
            }
            for path in oldManifest?.injectedFiles ?? [] {
                let file = try contained(path, in: oldBundle)
                let expected = (file.pathExtension.lowercased() == "bundle" ? "" : "Frameworks/") + file.lastPathComponent
                let rootDylib = file.pathExtension.lowercased() == "dylib" && path == file.lastPathComponent
                guard ["dylib", "framework", "bundle"].contains(file.pathExtension.lowercased()), path == expected || rootDylib else {
                    throw LCPluginError("旧应用的插件或资源缺失、路径无效：\(path)，已停止覆盖安装。")
                }
                // The incoming IPA owns conflicts; inherit only files it does not contain.
                if fm.fileExists(atPath: try contained(path, in: bundle).path) { continue }
                guard fm.fileExists(atPath: file.path) else {
                    throw LCPluginError("旧应用的插件或资源缺失：\(path)，已停止覆盖安装。")
                }
                items.append((file, path))
            }
        }
        guard !app.is32bit else { throw LCPluginError("直接注入插件暂不支持 32 位 Guest。") }
        if (!urls.isEmpty || !items.isEmpty) && (!app.dontInjectTweakLoader || !app.dontLoadTweakLoader) {
            throw LCPluginError("请先在应用设置中打开“不注入 TweakLoader”和“不加载 TweakLoader”。")
        }
        let info = try PropertyListSerialization.propertyList(from: Data(contentsOf: bundle.appendingPathComponent("Info.plist")), format: nil) as? [String: Any]
        guard let executable = info?["CFBundleExecutable"] as? String, !executable.isEmpty,
              executable == (executable as NSString).lastPathComponent else { throw LCPluginError("主程序文件名无效。") }
        let inspection = try LCAppPlugins.inspect(app: app)
        var removalPaths = paths
        let compatibilityRuntime = "Frameworks/CydiaSubstrate.framework"
        if !paths.isEmpty, previous?.injectedFiles.contains(compatibilityRuntime) == true,
           !paths.contains(compatibilityRuntime) {
            let runtimeIsNeeded = inspection.images.contains { image in
                guard image.exists, !image.id.hasPrefix(compatibilityRuntime + "/"),
                      !paths.contains(where: { image.id == $0 || image.id.hasPrefix($0 + "/") }) else { return false }
                // Preserve the runtime when a remaining image cannot be inspected safely.
                guard let dependencies = try? LCPluginMachO(url: contained(image.id, in: bundle)).dependencies else { return true }
                return dependencies.contains { ["CydiaSubstrate", "libsubstrate.dylib"].contains(($0 as NSString).lastPathComponent) }
            }
            if !runtimeIsNeeded { removalPaths.append(compatibilityRuntime) }
        }
        let workspace = fm.temporaryDirectory.appendingPathComponent("LCPluginImport-\(UUID().uuidString)")
        try fm.createDirectory(at: workspace, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: workspace) }
        for (index, url) in urls.enumerated() {
            guard url.isFileURL, LCAppPlugins.extensions.contains(url.pathExtension.lowercased()), !url.lastPathComponent.hasPrefix(".") else {
                throw LCPluginError("请选择 dylib、framework、bundle、deb 或 zip 插件文件。")
            }
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            let package = workspace.appendingPathComponent(String(index))
            if ["dylib", "framework", "bundle"].contains(url.pathExtension.lowercased()) {
                try fm.createDirectory(at: package, withIntermediateDirectories: true)
                try fm.copyItem(at: url, to: package.appendingPathComponent(url.lastPathComponent))
            } else { try LCUtils.extractPluginArchive(url.path, toPath: package.path) }
            let contents = try pluginItems(in: package, recursive: true)
            guard !contents.isEmpty else { throw LCPluginError("\(url.lastPathComponent) 内未找到可导入的库或资源。") }
            for item in contents {
                let ext = item.pathExtension.lowercased()
                let atRoot = ext == "bundle" || (ext == "dylib" && options.installAtRoot)
                let path = (atRoot ? "" : "Frameworks/") + item.lastPathComponent
                items.append((item, path))
                if ext == "dylib" {
                    let otherPath = (atRoot ? "Frameworks/" : "") + item.lastPathComponent
                    if previous?.injectedFiles.contains(otherPath) == true { removalPaths.append(otherPath) }
                }
            }
        }
        var destinations = Set<String>()
        for (item, path) in items {
            guard destinations.insert(path.lowercased()).inserted else { throw LCPluginError("插件包包含重名文件：\(item.lastPathComponent)") }
            _ = try regularFiles(in: item)
        }
        removalPaths = Array(Set(removalPaths)).sorted()
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
            let main = try contained(executable, in: staged)
            let extensions = try extensionExecutables(in: staged)
            let executables = [main] + extensions
            let executablePaths = Set(executables.map { String($0.path.dropFirst(staged.path.count + 1)) })
            var removedLoads: [String: Set<String>] = [:]
            if !removalPaths.isEmpty {
                guard removalPaths.allSatisfy({ path in
                    previous?.injectedFiles.contains(path) == true || inspection.images.contains { $0.id == path || $0.id.hasPrefix(path + "/") }
                }) else { throw LCPluginError("所选库不存在，请刷新列表。") }
                let removed = try removalPaths.map { try contained($0, in: staged) }
                for reference in inspection.references where removalPaths.contains(where: { reference.target == $0 || reference.target.hasPrefix($0 + "/") }) {
                    if executablePaths.contains(reference.loader) {
                        removedLoads[reference.loader, default: []].insert(reference.load)
                    } else if !removalPaths.contains(where: { reference.loader == $0 || reference.loader.hasPrefix($0 + "/") }) {
                        throw LCPluginError("\(reference.loader) 仍依赖 \(reference.target)，请先移除依赖它的插件。")
                    }
                }
                for file in removed where fm.fileExists(atPath: file.path) { try fm.removeItem(at: file) }
                injectedFiles.removeAll { path in removalPaths.contains { path == $0 || path.hasPrefix($0 + "/") } }
                images.removeAll { image in removalPaths.contains { image == $0 || image.hasPrefix($0 + "/") } }
            }
            let frameworks = staged.appendingPathComponent("Frameworks")
            try fm.createDirectory(at: frameworks, withIntermediateDirectories: true)
            var binaries: [URL] = []
            var previousTargets: [String: Set<String>] = [:]
            for (item, relative) in items {
                guard !executablePaths.contains(relative) else { throw LCPluginError("插件路径与应用可执行文件冲突：\(relative)") }
                let destination = try contained(relative, in: staged)
                for reference in inspection.references where executablePaths.contains(reference.loader) &&
                    (reference.target == relative || reference.target.hasPrefix(relative + "/")) {
                    removedLoads[reference.loader, default: []].insert(reference.load)
                    previousTargets[reference.loader, default: []].insert(reference.target)
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
            if !items.isEmpty, options.replaceSubstrateWithElleKit || (needsRuntime && !fm.fileExists(atPath: embeddedRuntime.path)) {
                if fm.fileExists(atPath: embeddedRuntime.path) { try fm.removeItem(at: embeddedRuntime) }
                try fm.copyItem(at: runtime, to: embeddedRuntime)
                if !injectedFiles.contains(compatibilityRuntime) { injectedFiles.append(compatibilityRuntime) }
                let runtimeBinary = try binaryURL(embeddedRuntime)
                if !binaries.contains(runtimeBinary) { binaries.insert(runtimeBinary, at: 0) }
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
                do { try macho.edit(replacements: replacements) }
                catch { throw LCPluginError("\(binary.lastPathComponent)：\(error.localizedDescription)") }
                try macho.write(to: binary)
                try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binary.path)
            }
            let addedImages = binaries.map { String($0.path.dropFirst(staged.path.count + 1)) }
            images = Array(Set(images + addedImages)).sorted()
            for target in executables {
                let relative = String(target.path.dropFirst(staged.path.count + 1))
                let remove = removedLoads[relative] ?? []
                let previouslyLinked = previousTargets[relative] ?? []
                let add = target == main || options.includeExtensions ? addedImages : addedImages.filter(previouslyLinked.contains)
                if add.isEmpty && remove.isEmpty { continue }
                do {
                    var macho = try LCPluginMachO(url: target)
                    try macho.requireARM64()
                    try macho.requireDecrypted()
                    let loads = try loadPaths(for: add, in: staged, executable: target, macho: macho, style: options.loadPath)
                    try macho.edit(add: loads, remove: remove, weak: options.weak)
                    try macho.write(to: target)
                    guard try LCPluginMachO(url: target).containsLoads(loads, absent: remove.subtracting(loads), weak: options.weak) else {
                        throw LCPluginError("插件加载项修改回读校验失败。")
                    }
                } catch {
                    throw LCPluginError("\(relative)：\(error.localizedDescription)")
                }
            }
            let manifest = Manifest(revision: 4, executable: executable,
                                    injectedFiles: injectedFiles.sorted(), images: images, options: options)
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

    static func extensionExecutables(in bundle: URL) throws -> [URL] {
        let fm = FileManager.default
        var result = Set<URL>()
        for directory in ["PlugIns", "Extensions"] {
            let root = try contained(directory, in: bundle)
            guard fm.fileExists(atPath: root.path) else { continue }
            for extensionBundle in try fm.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isSymbolicLinkKey], options: [.skipsHiddenFiles])
            where extensionBundle.pathExtension.lowercased() == "appex" {
                guard try extensionBundle.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true else { continue }
                let infoURL = try contained("Info.plist", in: extensionBundle)
                let info = try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as? [String: Any]
                guard let name = info?["CFBundleExecutable"] as? String, !name.isEmpty, name != ".", name != "..",
                      name == (name as NSString).lastPathComponent else {
                    throw LCPluginError("扩展缺少有效的 CFBundleExecutable：\(extensionBundle.lastPathComponent)")
                }
                result.insert(try contained(name, in: extensionBundle).resolvingSymlinksInPath())
            }
        }
        return result.sorted { $0.path < $1.path }
    }

    static func expandLoadPath(_ path: String, executableDirectory: URL, loaderDirectory: URL) -> URL? {
        for (token, directory) in [("@loader_path", loaderDirectory), ("@executable_path", executableDirectory)] {
            if path == token { return directory.resolvingSymlinksInPath() }
            if path.hasPrefix(token + "/") {
                return directory.appendingPathComponent(String(path.dropFirst(token.count + 1))).standardizedFileURL.resolvingSymlinksInPath()
            }
        }
        if path.hasPrefix("/") { return URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath() }
        return nil
    }

    static func loadPaths(for images: [String], in bundle: URL, executable: URL, macho: LCPluginMachO, style: LoadPath) throws -> [String] {
        let directory = executable.deletingLastPathComponent()
        let search = style == .rpath ? try macho.sliceSearchPaths : []
        let fm = FileManager.default
        return try images.map { image in
            let target = try contained(image, in: bundle).resolvingSymlinksInPath()
            let relative = relativePath(from: directory, to: target)
            let loaderPath = "@loader_path/" + relative
            if style == .loader { return loaderPath }
            if style == .executable { return "@executable_path/" + relative }

            // Use a short path only when all slices resolve it to this image.
            let directories = search.map { $0.map { expandLoadPath($0, executableDirectory: directory, loaderDirectory: directory) } }
            let suffixes = Set(directories.first?.compactMap { root -> String? in
                guard let root, target.path.hasPrefix(root.path + "/") else { return nil }
                return String(target.path.dropFirst(root.path.count + 1))
            } ?? []).sorted { ($0.utf8.count, $0) < ($1.utf8.count, $1) }
            if let suffix = suffixes.first(where: { suffix in
                directories.allSatisfy { roots in
                    for root in roots {
                        guard let root else { return false }
                        let candidate = root.appendingPathComponent(suffix).standardizedFileURL.resolvingSymlinksInPath()
                        if fm.fileExists(atPath: candidate.path) { return candidate.path == target.path }
                    }
                    return false
                }
            }) {
                return "@rpath/" + suffix
            }
            throw LCPluginError("现有 rpath 无法解析到插件：\(image)。请选择其他加载路径。")
        }
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
