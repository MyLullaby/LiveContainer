import Combine
import Foundation
import UniformTypeIdentifiers

final class SharePayload: ObservableObject {
    enum Kind {
        case loading
        case url(URL)
        case file(URL)
        case empty
        case failed(String)
    }

    @Published var kind: Kind = .loading

    var sharedURL: URL? {
        if case .url(let url) = kind {
            return url
        }
        return nil
    }
    
    static func load(from context: NSExtensionContext?) async throws -> SharePayload.Kind {
        guard let items = context?.inputItems as? [NSExtensionItem] else {
            return .empty
        }

        let providers = items.flatMap { $0.attachments ?? [] }
        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(UTType.url.identifier) {
                let item = try await provider.loadItem(forTypeIdentifier: UTType.url.identifier)
                if let url = item as? URL {
                    return url.isFileURL ? .file(url) : .url(url)
                }
                if let data = item as? Data, let string = String(data: data, encoding: .utf8), let url = URL(string: string) {
                    return url.isFileURL ? .file(url) : .url(url)
                }
                if let string = item as? String, let url = URL(string: string) {
                    return url.isFileURL ? .file(url) : .url(url)
                }
            }
        }
        for provider in providers {
            guard let type = provider.registeredTypeIdentifiers.first(where: {
                guard let content = UTType($0) else { return false }
                return content.conforms(to: .data)
            }) else { continue }
            let url: URL = try await withCheckedThrowingContinuation { continuation in
                provider.loadFileRepresentation(forTypeIdentifier: type) { url, error in
                    guard let url else {
                        continuation.resume(throwing: error ?? ShareExtensionError("无法读取分享文件。"))
                        return
                    }
                    do {
                        let fm = FileManager.default
                        let folder = fm.temporaryDirectory.appendingPathComponent("LCShare-\(UUID().uuidString)")
                        try fm.createDirectory(at: folder, withIntermediateDirectories: true)
                        let copy = folder.appendingPathComponent(url.lastPathComponent)
                        try fm.copyItem(at: url, to: copy)
                        continuation.resume(returning: copy)
                    } catch { continuation.resume(throwing: error) }
                }
            }
            return .file(url)
        }
        return .empty
    }
}

struct ShareContainer: Identifiable, Hashable {
    let id: String
    let folderName: String
    let name: String
    let isShared: Bool
}

struct ShareApp: Identifiable, Hashable {
    let id: String
    let relativeBundlePath: String
    let displayName: String
    let bundleIdentifier: String
    let isShared: Bool
    let isHidden: Bool
    let isLocked: Bool
    let isJITNeeded: Bool
    let containers: [ShareContainer]
    let iconURL: URL?
    let lastLaunched: Date?
    let installationDate: Date?
    let isBuiltInSideStore: Bool

    var primaryContainer: ShareContainer? {
        containers.first
    }
}

struct ShareLaunchItem: Identifiable, Hashable {
    let app: ShareApp
    let container: ShareContainer

    var id: String {
        "\(app.id)|\(container.id)"
    }
}

struct ShareExtensionError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? {
        message
    }
}
