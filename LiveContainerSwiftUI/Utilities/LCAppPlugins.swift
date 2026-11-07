import Foundation

enum LCAppPlugins {
    struct Image: Identifiable {
        let id: String
        let managed: Bool
        let linked: Bool
        let exists: Bool
    }

    struct Inspection {
        let images: [Image]
        let warnings: [String]
        let references: [Reference]
    }
    struct Reference {
        let loader: String
        let load: String
        let target: String
    }
    static let extensions: Set<String> = ["dylib", "deb", "zip"]

    static func inspect(app: LCAppInfo) throws -> Inspection {
        let fm = FileManager.default
        let bundle = URL(fileURLWithPath: app.bundlePath()).resolvingSymlinksInPath()
        let manifest = try LCPluginPreparation.manifest(in: bundle)
        let info = try PropertyListSerialization.propertyList(from: Data(contentsOf: bundle.appendingPathComponent("Info.plist")), format: nil) as? [String: Any]
        guard let executable = info?["CFBundleExecutable"] as? String,
              executable == (executable as NSString).lastPathComponent, !executable.isEmpty else {
            throw LCPluginError("主程序文件名无效。")
        }
        let main = bundle.appendingPathComponent(executable)
        var files = Set<URL>()
        var warnings: [String] = []
        if let enumerator = fm.enumerator(at: bundle, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]) {
            for case let url as URL in enumerator {
                if url.pathExtension.lowercased() == "dylib", try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
                    files.insert(url.resolvingSymlinksInPath())
                } else if url.pathExtension.lowercased() == "framework" {
                    do { files.insert(try LCPluginPreparation.binaryURL(url).resolvingSymlinksInPath()) }
                    catch { warnings.append(error.localizedDescription) }
                }
            }
        }
        func expand(_ path: String, loader: URL) -> URL? {
            if path.hasPrefix("@loader_path/") { return loader.appendingPathComponent(String(path.dropFirst(13))).standardizedFileURL.resolvingSymlinksInPath() }
            if path.hasPrefix("@executable_path/") { return bundle.appendingPathComponent(String(path.dropFirst(17))).standardizedFileURL.resolvingSymlinksInPath() }
            if path.hasPrefix("/") { return URL(fileURLWithPath: path).resolvingSymlinksInPath() }
            return nil
        }
        var queue: [(URL, [URL])] = [(main, [])]
        var visited = Set<URL>()
        var linked = Set<URL>()
        var references: [Reference] = []
        while !queue.isEmpty {
            let (image, inheritedPaths) = queue.removeLast()
            guard visited.insert(image).inserted else { continue }
            let loads: [String]
            let paths: [URL]
            do {
                let macho = try LCPluginMachO(url: image)
                loads = try macho.dependencies
                paths = try macho.runtimeSearchPaths.sorted().compactMap { expand($0 + "/", loader: image.deletingLastPathComponent()) } + inheritedPaths
            } catch {
                warnings.append(error.localizedDescription)
                continue
            }
            for load in loads {
                if load.hasPrefix("/System/") || load.hasPrefix("/usr/lib/") { continue }
                var candidates: [URL]
                if load.hasPrefix("@rpath/") {
                    candidates = paths.map { $0.appendingPathComponent(String(load.dropFirst(7))).standardizedFileURL.resolvingSymlinksInPath() }
                } else {
                    candidates = expand(load, loader: image.deletingLastPathComponent()).map { [$0] } ?? []
                }
                candidates = candidates.filter { $0.path.hasPrefix(bundle.path + "/") }
                guard let target = candidates.first(where: { fm.fileExists(atPath: $0.path) }) ?? candidates.first else {
                    warnings.append("\(image.lastPathComponent)：未能在应用内解析依赖 \(load)")
                    continue
                }
                files.insert(target)
                linked.insert(target)
                references.append(Reference(loader: String(image.path.dropFirst(bundle.path.count + 1)), load: load,
                                            target: String(target.path.dropFirst(bundle.path.count + 1))))
                if fm.fileExists(atPath: target.path) { queue.append((target, paths)) }
            }
        }
        let managed = Set((manifest?.images ?? []).map { bundle.appendingPathComponent($0).standardizedFileURL.resolvingSymlinksInPath() })
        files.formUnion(managed)
        let images = files.filter { $0 != main && $0.path.hasPrefix(bundle.path + "/") }.map { file in
            Image(id: String(file.path.dropFirst(bundle.path.count + 1)), managed: managed.contains(file),
                  linked: linked.contains(file), exists: fm.fileExists(atPath: file.path))
        }.sorted { $0.id.localizedStandardCompare($1.id) == .orderedAscending }
        return Inspection(images: images, warnings: Array(Set(warnings)).sorted(), references: references)
    }

}
