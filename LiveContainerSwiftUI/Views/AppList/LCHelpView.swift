//
//  LCHelpView.swift
//  LiveContainerSwiftUI
//
//  Created by s s on 2025/1/4.
//

import SwiftUI

struct LCHelpView : View {
    @Binding var isPresent : Bool

    private var returnGestureDiagnostics: String {
        let lines = ["LCReturnToLibraryBootstrap", "LCReturnToLibraryLoadedHooks", "LCReturnToLibraryLastTap", "LCReturnToLibraryLastReturn"]
            .compactMap { LCUtils.appGroupUserDefault.string(forKey: $0) }
        return lines.isEmpty ? "lc.helpView.noReturnGestureDiagnostics".loc : lines.joined(separator: "\n\n")
    }
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading) {
                    Text("lc.helpView.text1")
                    Text("")
                    Text("lc.helpView.text2")
                    Text("")
                    Text("lc.helpView.returnToLibraryGesture")
                    Divider()
                    Text("lc.helpView.returnGestureDiagnostics")
                        .font(.headline)
                    Text(verbatim: returnGestureDiagnostics)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    Button("lc.common.copy") {
                        UIPasteboard.general.string = returnGestureDiagnostics
                    }
                }
                .padding()
            }
            .navigationTitle("lc.helpView.title")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem {
                    Button("lc.common.done") {
                        isPresent = false
                    }
                }
            }
        }
    }
}
