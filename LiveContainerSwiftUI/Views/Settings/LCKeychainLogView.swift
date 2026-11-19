import SwiftUI

struct LCKeychainLogView: View {
    @State private var logs = ""
    @State private var clearFailed = false
    @State private var showingShare = false
    @State private var reloadID = UUID()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ScrollView {
            Text(logs.isEmpty ? "暂无异常记录。" : logs)
                .font(.system(.footnote, design: .monospaced))
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
                .padding()
        }
        .navigationTitle("LC 钥匙串诊断")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button("刷新") { reload() }
                Button("分享") { showingShare = true }.disabled(logs.isEmpty)
                Button("清空", role: .destructive) {
                    clearFailed = !LCDebugLog.clearKeychainLogs()
                    reload()
                }
            }
        }
        .sheet(isPresented: $showingShare) {
            ActivityViewController(activityItems: [logs], applicationActivities: nil)
        }
        .alert("无法清空日志", isPresented: $clearFailed) { Button("好", role: .cancel) {} }
        .onAppear { reload() }
        .onChange(of: scenePhase) { phase in if phase == .active { reload() } }
    }

    private func reload() {
        let id = UUID()
        reloadID = id
        Task {
            let contents = await Task.detached { LCDebugLog.readKeychainLogs() }.value
            if reloadID == id { logs = contents }
        }
    }
}
