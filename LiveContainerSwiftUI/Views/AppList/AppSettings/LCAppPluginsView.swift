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
    @State private var classifications: [String: Bool] = [:]
    @State private var classificationChanged = false

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
                    Text("第三方插件：\(inspection.images.filter { $0.isPlugin && $0.exists }.count) 个")
                    ForEach(inspection.images.filter { $0.isPlugin && $0.exists }) { image in
                        libraryRow(image)
                    }
                    DisclosureGroup("其他库（\(inspection.images.filter { !$0.isPlugin && $0.exists }.count)）") {
                        ForEach(inspection.images.filter { !$0.isPlugin && $0.exists }) { image in
                            libraryRow(image)
                        }
                    }
                    ForEach(inspection.warnings, id: \.self) { warning in
                        Text(warning).font(.footnote).foregroundColor(.orange).textSelection(.enabled)
                    }
                } header: { Text("插件管理") } footer: {
                    Text("包含 LC 导入和根据注入特征识别的插件。未识别的插件可在“其他库”中纳入管理；长按已识别项可标记为应用原有库。调整后点击“确认并隐藏插件”，下次启动生效；分类不会改变加载方式。")
                }
            }
            Section {
                Button(classificationChanged ? "确认并隐藏插件（有未保存修改）" : "确认并隐藏插件", systemImage: "checkmark.shield") { confirmVisibility() }
                    .disabled(inspection == nil)
                Button("导入插件", systemImage: "square.and.arrow.down") { choosingFiles = true }
                Button("刷新列表", systemImage: "arrow.clockwise") { reload() }
                Button("移除全部插件", role: .destructive) {
                    do {
                        let bundle = URL(fileURLWithPath: model.appInfo.bundlePath())
                        let resources = try LCPluginPreparation.manifest(in: bundle)?.injectedFiles ?? []
                        removal = Array(Set(resources + (inspection?.images.filter { $0.isPlugin && $0.exists }.map { removalPath($0.id) } ?? []))).sorted()
                        if removal.isEmpty { message = "没有可移除的插件。" }
                        else { confirmingRemoval = true }
                    } catch { message = error.localizedDescription }
                }
            } footer: {
                Text("支持 dylib、deb、zip。导入后立即修改并签名，成功后才更新列表；同名库直接覆盖。无需保留来源文件，重新修改请再次导入。移除全部处理列表中的第三方插件及 LC 导入资源，保留应用数据。")
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

    private func libraryRow(_ image: LCAppPlugins.Image) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(image.id).font(.footnote).textSelection(.enabled)
                Spacer()
                if image.isPlugin {
                    Button(role: .destructive) {
                        removal = [removalPath(image.id)]
                        confirmingRemoval = true
                    } label: { Image(systemName: "trash") }
                        .buttonStyle(.borderless).accessibilityLabel("移除 \(image.id)")
                } else {
                    Button("纳入插件管理") { classify(image, asPlugin: true) }
                        .font(.caption).buttonStyle(.borderless)
                }
            }
            Text("\(image.managed ? "LC 导入" : image.isPlugin ? "IPA 内第三方插件" : "来源未确认") · \(image.linked ? "在静态加载链中" : "文件存在")")
                .font(.caption).foregroundColor(.secondary)
        }
        .contextMenu {
            if image.isPlugin && !image.managed {
                Button("标记为应用原有库") { classify(image, asPlugin: false) }
            }
        }
    }

    private func classify(_ image: LCAppPlugins.Image, asPlugin: Bool) {
        classifications[image.id] = asPlugin
        classificationChanged = true
        reload()
    }

    private func confirmVisibility() {
        do {
            for container in model.appInfo.containers {
                if LCSharedUtils.getContainerUsingLCScheme(withFolderName: container.folderName) != nil {
                    throw LCPluginError("请先退出正在运行的应用，再确认隐藏插件。")
                }
            }
            let count = try LCAppPlugins.confirmVisibility(app: model.appInfo, classifications: classifications)
            model.uiHideLiveContainer = true
            classificationChanged = false
            reload()
            message = "已确认隐藏 \(count) 个插件库，下次启动应用生效。插件仍会正常加载。"
        } catch { message = error.localizedDescription }
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
            if !classificationChanged { classifications = try LCAppPlugins.savedClassifications(app: model.appInfo) }
            inspection = try LCAppPlugins.inspect(app: model.appInfo, classifications: classifications)
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
