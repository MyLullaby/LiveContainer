import SwiftUI

final class LCPluginImportRequest: Identifiable {
    let id = UUID()
    let files: [URL]
    private let temporary: URL

    init(files: [URL], resolveShareBookmark: Bool) throws {
        let fm = FileManager.default
        temporary = fm.temporaryDirectory.appendingPathComponent("LCPluginShare-\(id.uuidString)")
        try fm.createDirectory(at: temporary, withIntermediateDirectories: true)
        do {
            var copies: [URL] = []
            for var url in files {
                guard url.isFileURL, LCAppPlugins.extensions.contains(url.pathExtension.lowercased()) else {
                    throw LCPluginError("请选择 dylib、deb 或 zip 插件文件。")
                }
                if resolveShareBookmark, !fm.isReadableFile(atPath: url.path),
                   let bookmark = LCUtils.appGroupUserDefault.data(forKey: "LCLaunchExtensionFileBookmark") {
                    var stale = false
                    let resolved = try URL(resolvingBookmarkData: bookmark, options: .init(rawValue: 1 << 10),
                                           relativeTo: nil, bookmarkDataIsStale: &stale)
                    guard resolved.lastPathComponent == url.lastPathComponent else { throw LCPluginError("分享文件书签不匹配，请重新分享。") }
                    url = resolved
                }
                let accessed = url.startAccessingSecurityScopedResource()
                defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                let copy = temporary.appendingPathComponent(url.lastPathComponent)
                try fm.copyItem(at: url, to: copy)
                copies.append(copy)
                let inbox = LCPath.lcGroupDocPath.appendingPathComponent("PluginInbox").resolvingSymlinksInPath()
                let parent = url.deletingLastPathComponent().resolvingSymlinksInPath()
                if parent.deletingLastPathComponent() == inbox, UUID(uuidString: parent.lastPathComponent) != nil {
                    try? fm.removeItem(at: parent)
                }
            }
            self.files = copies
        } catch {
            try? fm.removeItem(at: temporary)
            throw error
        }
    }

    deinit { try? FileManager.default.removeItem(at: temporary) }
}

struct LCPluginImportView: View {
    let request: LCPluginImportRequest
    @EnvironmentObject private var sharedModel: SharedModel
    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var message: String?
    @State private var target: LCAppModel?
    @AppStorage("LCPluginLastTarget", store: LCUtils.appGroupUserDefault) private var lastTarget = ""
    @AppStorage("LCIconStyle", store: LCUtils.appGroupUserDefault) private var iconStyle = 0
    @Environment(\.colorScheme) private var colorScheme

    private var apps: [LCAppModel] {
        let visible = (sharedModel.apps + (sharedModel.isHiddenAppUnlocked ? sharedModel.hiddenApps : []))
            .filter { !($0.appInfo is BuiltInSideStoreAppInfo) }
        return visible.filter { $0.appInfo.relativeBundlePath == lastTarget }
            + visible.filter { $0.appInfo.relativeBundlePath != lastTarget }
    }

    var body: some View {
        NavigationView {
            List {
                Section {
                    ForEach(apps, id: \.self) { app in
                        Button { importInto(app) } label: {
                            HStack(spacing: 12) {
                                Image(uiImage: app.appInfo.iconIsDarkIcon(iconStyle == 1 || (iconStyle == 2 && colorScheme == .dark)) ?? UIImage())
                                    .resizable().scaledToFit().frame(width: 44, height: 44)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))
                                Text(app.appInfo.displayName() ?? "App").foregroundColor(.primary)
                                Spacer()
                                if app.appInfo.relativeBundlePath == lastTarget {
                                    Text("上次选择").font(.caption).foregroundColor(.secondary)
                                }
                            }
                        }
                    }
                } header: { Text("选择导入到哪个应用") }
                if let target {
                    NavigationLink("查看插件列表") { LCAppPluginsView(model: target) }
                }
                if busy { ProgressView("正在导入并准备插件…") }
            }
            .disabled(busy)
            .navigationTitle("导入插件")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("lc.common.close".loc) { dismiss() }.disabled(busy) } }
            .alert("插件导入", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
                Button("lc.common.ok".loc) { message = nil }
            } message: { Text(message ?? "") }
        }
        .navigationViewStyle(.stack)
    }

    private func importInto(_ app: LCAppModel) {
        busy = true
        Task { @MainActor in
            defer { busy = false }
            do {
                if app.appInfo.isLocked && !sharedModel.isHiddenAppUnlocked {
                    guard try await LCUtils.authenticateUser() else { return }
                }
                lastTarget = app.appInfo.relativeBundlePath ?? ""
                target = app
                try await app.updatePlugins(importing: request.files)
                message = "已导入到 \(app.appInfo.displayName() ?? "App")。"
            } catch { message = error.localizedDescription }
        }
    }
}
