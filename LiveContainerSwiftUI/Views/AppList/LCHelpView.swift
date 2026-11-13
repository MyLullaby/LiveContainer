//
//  LCHelpView.swift
//  LiveContainerSwiftUI
//
//  Created by s s on 2025/1/4.
//

import SwiftUI

struct LCHelpView : View {
    @Binding var isPresent : Bool
    @State private var helpURL = URL(string: "https://livecontainer.github.io/docs/faq")!
    @State private var showFAQ = false

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading) {
                    Text("lc.helpView.text1")
                    Text("")
                    Text("lc.helpView.text2")
                    Text("")
                    Text("lc.helpView.returnToLibraryGesture")
                    Button("FAQ") {
                        showFAQ = true
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
        .sheet(isPresented: $showFAQ) {
            SafariView(url: $helpURL)
        }
    }
}
