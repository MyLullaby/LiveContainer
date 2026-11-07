import SwiftUI
import UniformTypeIdentifiers

struct LCAppPluginsView: View {
    @ObservedObject var model: LCAppModel
    @State private var names: [String] = []
    @State private var choosingFiles = false
    @State private var busy = false
    @State private var message: String?

    var body: some View {
        List {
            Section {
                ForEach(names, id: \.self) { name in
                    HStack {
                        Text(name)
                        Spacer()
                        Button(role: .destructive) {
                            update(removing: name)
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("删除 \(name)")
                    }
                }
                Button("导入插件", systemImage: "square.and.arrow.down") { choosingFiles = true }
                Button("重新检查并应用", systemImage: "arrow.clockwise") { update() }
            } footer: {
                Text("支持 dylib、deb、zip。同名文件重新导入会替换旧文件。列表或文件内容变化后才重新准备；失败时保留列表，补齐依赖后可重试。此列表独立于旧版 TweakLoader 插件文件夹。")
            }
            if busy { ProgressView("正在准备插件…") }
        }
        .disabled(busy || model.isAppRunning || model.isSigningInProgress)
        .navigationTitle("应用插件")
        .onAppear { reload() }
        .betterFileImporter(isPresented: $choosingFiles, types: [.dylib, .deb, .zip], multiple: true) { urls in
            update(importing: urls)
        } onDismiss: { choosingFiles = false }
        .alert("插件处理", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("lc.common.ok".loc) { message = nil }
        } message: { Text(message ?? "") }
    }

    private func reload() {
        do { names = try LCAppPlugins.names(app: model.appInfo) }
        catch { message = error.localizedDescription }
    }

    private func update(importing urls: [URL] = [], removing name: String? = nil) {
        busy = true
        Task { @MainActor in
            defer { busy = false; reload() }
            do { try await model.updatePlugins(importing: urls, removing: name) }
            catch { message = "\(error.localizedDescription)\n请检查插件列表，调整后重新应用。" }
        }
    }
}
