//
//  LCAppIconPickerView.swift
//  LiveContainerSwiftUI
//
//  Created by LiveContainer on 2024/8/21.
//

import SwiftUI

struct LCAppIconPickerView: View {
    @State private var currentIconName: String? = UIApplication.shared.alternateIconName
    @State var errorShow = false
    @State var errorInfo = ""
    
    private let icons: [(name: String, previewImage: String, alternateIconName: String)] = [
        ("Books", "IconPreviewBooks", "AppIconBooks"),
        ("Calendar", "IconPreviewCalendar", "AppIconCalendar"),
        ("Sparkles", "IconPreviewSparkles", "AppIconSparkles"),
    ]
    
    var body: some View {
        List {
            ForEach(icons, id: \.alternateIconName) { icon in
                Button {
                    changeAppIcon(to: icon.alternateIconName)
                } label: {
                    HStack(spacing: 12) {
                        Image(icon.previewImage)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 60, height: 60)
                            .clipShape(RoundedRectangle(cornerRadius: 13.5))
                            .overlay(
                                RoundedRectangle(cornerRadius: 13.5)
                                    .stroke(Color.gray.opacity(0.3), lineWidth: 0.5)
                            )
                        Text(icon.name)
                            .foregroundColor(.primary)
                        Spacer()
                        if currentIconName == icon.alternateIconName {
                            Image(systemName: "checkmark")
                                .foregroundColor(.accentColor)
                                .font(.body.weight(.semibold))
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .navigationBarTitle("lc.settings.appIcon".loc, displayMode: .inline)
        .alert("lc.common.error".loc, isPresented: $errorShow) {
        } message: {
            Text(errorInfo)
        }
    }
    
    func changeAppIcon(to iconName: String) {
        guard currentIconName != iconName else { return }
        UIApplication.shared.setAlternateIconName(iconName) { error in
            if let error = error {
                errorInfo = error.localizedDescription
                errorShow = true
            } else {
                currentIconName = iconName
            }
        }
    }
}
