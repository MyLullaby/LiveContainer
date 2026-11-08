import Foundation

enum LCGuestURLRouting {
    @MainActor static func open(_ url: URL, delegate: LCAppModelDelegate) async throws {
        guard let request = LCGuestURLRouter.request(for: url),
              let bundle = request["bundle-name"] as? String,
              let original = request["url"] as? String, let scheme = URL(string: original)?.scheme?.lowercased() else {
            LCDebugLog.record("host rejected invalid request", category: "GuestURL")
            throw LCPluginError("应用间跳转请求无效或已过期，请返回原应用重试。")
        }
        let container = request["container-folder-name"] as? String
        if LCDebugLog.isEnabled() {
            LCDebugLog.record("host received scheme=\(scheme) bundle=\(bundle) container=\(container ?? "default")", category: "GuestURL")
        }
        let model = DataManager.shared.model
        try model.reloadApps()
        let apps = model.apps + model.hiddenApps
        guard let app = apps.first(where: { $0.appInfo.isShared && $0.appInfo.relativeBundlePath == bundle }),
              container == nil || app.appInfo.containers.contains(where: { $0.folderName == container }),
              (app.appInfo.urlSchemes() as? [String] ?? []).contains(where: { $0.lowercased() == scheme }) else {
            LCDebugLog.record("host rejected target metadata mismatch", category: "GuestURL")
            throw LCPluginError("未找到目标应用或数据容器。")
        }
        app.delegate = delegate
        if let container, await app.bringExistingMultitaskWindowIfNeeded(dataUUID: container, urlScheme: url.absoluteString) {
            LCDebugLog.record("host delivered to existing window", category: "GuestURL")
            return
        }
        LCDebugLog.record("host launching installed target", category: "GuestURL")
        try await app.runApp(multitask: false, containerFolderName: container, urlStr: url.absoluteString)
    }
}
