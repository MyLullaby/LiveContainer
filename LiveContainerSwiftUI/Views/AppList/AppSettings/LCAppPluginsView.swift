import SwiftUI
import UniformTypeIdentifiers

struct LCAppPluginsView: View {
    @ObservedObject var model: LCAppModel
    @State private var choosingFiles = false
    @State private var busy = false
    @State private var message: String?
    @State private var inspection: LCAppPlugins.Inspection?
    @State private var removal: [String] = []
    @State private var confirmingRemoval = false
    @State private var launchDiagnostic: [String: Any] = [:]

    var body: some View {
        List {
            if let stage = launchDiagnostic["stage"] as? String {
                Section {
                    Text(launchStageDescription(stage))
                    if let date = launchDiagnostic["date"] as? Date { Text(date, style: .date); Text(date, style: .time) }
                    if let error = launchDiagnostic["error"] as? String {
                        Text(error).font(.footnote).foregroundColor(.red).textSelection(.enabled)
                    }
                } header: { Text("上次启动记录") } footer: {
                    Text("记录最后到达的启动阶段，用于缩小黑屏范围；不能仅凭这一项确定是哪个插件出错。进入主程序也不代表界面已正常显示。")
                }
            }
            if let inspection {
                Section {
                    Text("LC 管理的库：\(inspection.images.filter { $0.managed && $0.exists }.count) 个")
                    Text("IPA 内其他库：\(inspection.images.filter { !$0.managed && $0.exists }.count) 个")
                    ForEach(inspection.images.filter(\.exists)) { image in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(image.id).font(.footnote).textSelection(.enabled)
                                Spacer()
                                Button(role: .destructive) {
                                    removal = [removalPath(image.id)]
                                    confirmingRemoval = true
                                } label: { Image(systemName: "trash") }
                                    .buttonStyle(.borderless).accessibilityLabel("移除 \(image.id)")
                            }
                            Text("\(image.managed ? "LC 导入" : "IPA 内置／其他工具导入") · \(image.linked ? "在静态加载链中" : "文件存在")")
                                .font(.caption).foregroundColor(.secondary)
                        }
                    }
                    ForEach(inspection.warnings, id: \.self) { warning in
                        Text(warning).font(.footnote).foregroundColor(.orange).textSelection(.enabled)
                    }
                } header: { Text("实际库检测") } footer: {
                    Text("列表来自 App 内实际存在的库。其他库包含应用自带依赖及其他工具注入的库，请勿随意移除。静态加载链不代表插件运行成功。")
                }
            }
            Section {
                Button("导入插件", systemImage: "square.and.arrow.down") { choosingFiles = true }
                Button("刷新列表", systemImage: "arrow.clockwise") { reload() }
                Button("移除全部 LC 导入内容", role: .destructive) {
                    do {
                        let bundle = URL(fileURLWithPath: model.appInfo.bundlePath())
                        removal = try LCPluginPreparation.manifest(in: bundle)?.injectedFiles ?? []
                        if removal.isEmpty { message = "没有可移除的 LC 导入内容。" }
                        else { confirmingRemoval = true }
                    } catch { message = error.localizedDescription }
                }
            } footer: {
                Text("支持 dylib、deb、zip。导入后立即修改并签名，成功后才更新列表；同名库直接覆盖。无需保留来源文件，重新修改请再次导入。移除全部仅处理 LC 记录的内容，保留应用数据。")
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
        .confirmationDialog("确认从 App 中移除所选库或资源？", isPresented: $confirmingRemoval, titleVisibility: .visible) {
            Button("移除并修改 App", role: .destructive) {
                update(removing: removal)
            }
        } message: { Text("\(removal.joined(separator: "\n"))\n移除应用自带依赖可能导致应用无法启动。") }
    }

    private func removalPath(_ image: String) -> String {
        let components = image.split(separator: "/").map(String.init)
        if let index = components.firstIndex(where: { $0.lowercased().hasSuffix(".framework") }) {
            return components[...index].joined(separator: "/")
        }
        return image
    }

    private func reload() {
        launchDiagnostic = NSDictionary(contentsOfFile: URL(fileURLWithPath: model.appInfo.bundlePath()).appendingPathComponent("LCPluginLaunch.plist").path) as? [String: Any] ?? [:]
        inspection = nil
        do {
            inspection = try LCAppPlugins.inspect(app: model.appInfo)
        }
        catch { message = error.localizedDescription }
    }

    private func launchStageDescription(_ stage: String) -> String {
        switch stage {
        case "loadingImages": return "停在加载主程序、依赖库或执行初始化代码期间。"
        case "loadFailed": return "动态加载失败，错误如下。"
        case "imagesLoaded": return "动态库加载已返回，停在后续启动准备阶段。"
        case "bundleFailed": return "应用 Bundle 加载失败。"
        case "entryPointMissing": return "未找到应用主程序入口。"
        case "enteringMain": return "已准备进入 Guest 主程序。"
        case "mainReturned": return "Guest 主程序已返回。"
        default: return stage
        }
    }

    private func update(importing urls: [URL] = [], removing paths: [String] = []) {
        busy = true
        Task { @MainActor in
            defer { busy = false; reload() }
            do { try await model.updatePlugins(importing: urls, removing: paths) }
            catch { message = "\(error.localizedDescription)\n原 App 未被替换，请调整文件后重新导入或移除。" }
        }
    }
}
