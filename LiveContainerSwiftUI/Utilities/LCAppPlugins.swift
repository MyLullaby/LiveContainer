import Foundation

enum LCAppPlugins {
    // Keep sources inside the app so moving or deleting the app carries its plugin list too.
    private static let directoryName = ".LCPlugins"
    static let extensions: Set<String> = ["dylib", "deb", "zip"]

    static func directory(app: LCAppInfo) -> URL {
        URL(fileURLWithPath: app.bundlePath()).appendingPathComponent(directoryName)
    }

    static func names(app: LCAppInfo) throws -> [String] {
        let root = directory(app: app)
        guard FileManager.default.fileExists(atPath: root.path) else { return [] }
        return try FileManager.default.contentsOfDirectory(atPath: root.path)
            .filter { $0.hasSuffix(".plugin") }.map { String($0.dropLast(7)) }
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    static func importFiles(_ urls: [URL], app: LCAppInfo) throws {
        let fm = FileManager.default
        let root = directory(app: app)
        let staged = root.deletingLastPathComponent().appendingPathComponent(".LCPluginImport-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: staged) }
        if fm.fileExists(atPath: root.path) {
            try fm.copyItem(at: root, to: staged)
        } else {
            try fm.createDirectory(at: staged, withIntermediateDirectories: true)
        }
        for url in urls {
            guard url.isFileURL, extensions.contains(url.pathExtension.lowercased()),
                  !url.lastPathComponent.hasPrefix(".") else {
                throw LCPluginError("请选择 dylib、deb 或 zip 插件文件。")
            }
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            let package = staged.appendingPathComponent(url.lastPathComponent + ".plugin", isDirectory: true)
            if fm.fileExists(atPath: package.path) { try fm.removeItem(at: package) }
            if url.pathExtension.lowercased() == "dylib" {
                try fm.createDirectory(at: package, withIntermediateDirectories: true)
                try fm.copyItem(at: url, to: package.appendingPathComponent(url.lastPathComponent))
            } else {
                try LCUtils.extractPluginArchive(url.path, toPath: package.path)
            }
            let contents = try LCPluginPreparation.pluginItems(in: package, recursive: true)
            guard !contents.isEmpty else { throw LCPluginError("\(url.lastPathComponent) 内未找到 dylib、framework 或资源 bundle。") }
        }
        let items = try LCPluginPreparation.pluginItems(in: staged, recursive: true)
        var names = Set<String>()
        for item in items {
            guard names.insert(item.lastPathComponent.lowercased()).inserted else {
                throw LCPluginError("插件包含重名文件：\(item.lastPathComponent)，请先移除重复插件。")
            }
        }
        if fm.fileExists(atPath: root.path) {
            try LCPluginPreparation.commit(staged: staged, to: root)
        } else {
            try fm.moveItem(at: staged, to: root)
        }
    }

    static func remove(_ name: String, app: LCAppInfo) throws {
        guard try names(app: app).contains(name) else { throw LCPluginError("插件不存在。") }
        try FileManager.default.removeItem(at: directory(app: app).appendingPathComponent(name + ".plugin"))
    }

    static func preserveSources(from old: LCAppInfo, to new: LCAppInfo) throws {
        let fm = FileManager.default
        let source = directory(app: old)
        guard fm.fileExists(atPath: source.path) else { return }
        let destination = directory(app: new)
        if fm.fileExists(atPath: destination.path) { try fm.removeItem(at: destination) }
        try fm.copyItem(at: source, to: destination)
    }
}
