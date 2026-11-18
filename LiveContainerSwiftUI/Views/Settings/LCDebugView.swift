import SwiftUI
import UIKit

struct LCDebugView: View {
    @AppStorage("LCKeychainShadowEnabled", store: LCUtils.appGroupUserDefault) private var keychainShadowEnabled = false
    @State private var enabled = LCDebugLog.isEnabled()
    @State private var logs = ""
    @State private var error = ""
    @State private var loading = false
    @State private var reloadID = UUID()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        VStack(alignment: .leading) {
            Toggle("开启 Debug 模式", isOn: Binding(get: { enabled }, set: { value in
                if LCDebugLog.setLoggingEnabled(value) {
                    enabled = value
                    reload()
                } else {
                    error = "无法修改 Debug 模式，请检查共享目录是否可用。"
                }
            }))
            .padding(.horizontal)
            Text("开启后集中记录 LC1、LC2、LC3 和多任务中的启动、应用间跳转与返回列表日志。复现启动问题前，请先开启并重启相关 Guest App。日志最多保留约 4 MB，超出后清理较早记录。")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .padding(.horizontal)
            Toggle("钥匙串影子验证（实验）", isOn: $keychainShadowEnabled)
                .disabled(!enabled)
                .padding(.horizontal)
            Text("需开启 Debug 并重启 Guest App。系统仍提供真实结果；普通密码/token 的可识别条目会加密保存在各自数据目录的 Library/LCKeychainShadow，后续读取时先比较再导入。日志不包含密码或 token；未完整导入及不支持的请求会单独标记。此模式有额外磁盘开销，排查结束后请关闭并重启 Guest。关闭或清空日志不会删除影子数据，影子目录及其中的密钥暂不属于正式迁移格式。")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .padding(.horizontal)
            if enabled {
                ScrollView {
                    Text(logs.isEmpty ? "暂无日志，请复现问题后刷新。" : logs)
                        .font(.system(.footnote, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding()
                }
            } else {
                Text("Debug 模式已关闭，停止记录并隐藏日志；已有记录保留，可手动清空。")
                    .foregroundStyle(.secondary)
                    .padding()
                Spacer()
            }
        }
        .navigationTitle("Debug 模式")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button("刷新") { reload() }.disabled(!enabled || loading)
                Button("复制") { UIPasteboard.general.string = logs }.disabled(!enabled || loading || logs.isEmpty)
                Button("清空", role: .destructive) {
                    if LCDebugLog.clearLogs() { reload() } else { error = "无法清空 Debug 日志。" }
                }
            }
        }
        .alert("Debug", isPresented: Binding(get: { !error.isEmpty }, set: { if !$0 { error = "" } })) {
            Button("好", role: .cancel) { error = "" }
        } message: { Text(error) }
        .onAppear { reload() }
        .onChange(of: scenePhase) { phase in if phase == .active { reload() } }
    }

    private func reload() {
        let id = UUID()
        reloadID = id
        enabled = LCDebugLog.isEnabled()
        guard enabled else { logs = ""; return }
        loading = true
        Task {
            let contents = await Task.detached { LCDebugLog.readLogs() }.value
            guard reloadID == id else { return }
            logs = LCDebugLog.isEnabled() ? contents : ""
            loading = false
        }
    }
}
