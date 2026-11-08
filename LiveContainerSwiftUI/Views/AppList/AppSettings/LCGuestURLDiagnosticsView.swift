import SwiftUI
import UIKit

struct LCGuestURLDiagnosticsView: View {
    let bundleName: String
    @State private var diagnostics = ""
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ScrollView {
            Text(diagnostics)
                .font(.system(.footnote, design: .monospaced))
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
                .padding()
        }
        .navigationTitle("应用间跳转诊断")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button("刷新") { reload() }
                Button("复制") { UIPasteboard.general.string = diagnostics }
            }
        }
        .onAppear { reload() }
        .onChange(of: scenePhase) { phase in
            if phase == .active { reload() }
        }
    }

    private func reload() {
        diagnostics = LCGuestURLRouter.diagnostics(forBundleName: bundleName)
    }
}
