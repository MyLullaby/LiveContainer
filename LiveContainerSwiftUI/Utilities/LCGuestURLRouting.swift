import Foundation

enum LCGuestURLRouting {
    @MainActor static func open(_ url: URL) async throws {
        guard let request = LCGuestURLRouter.request(for: url),
              let bundle = request["bundle-name"] as? String,
              let container = request["container-folder-name"] as? String,
              let original = request["url"] as? String, let scheme = URL(string: original)?.scheme?.lowercased() else {
            LCDebugLog.record("host rejected invalid request", category: "GuestURL")
            throw LCPluginError("应用间跳转请求无效或已过期，请返回原应用重试。")
        }
        if LCDebugLog.isEnabled() {
            LCDebugLog.record("host received scheme=\(scheme) bundle=\(bundle) container=\(container)", category: "GuestURL")
        }
        let model = DataManager.shared.model
        try model.reloadApps()
        guard MultitaskManager.isUsing(container: container) else {
            LCDebugLog.record("host rejected stopped target", category: "GuestURL")
            throw LCPluginError("目标应用已停止运行，请先手动打开后重试。")
        }
        let apps = model.apps + model.hiddenApps
        guard let app = apps.first(where: { $0.appInfo.relativeBundlePath == bundle }),
              app.appInfo.containers.contains(where: { $0.folderName == container }),
              (app.appInfo.urlSchemes() as? [String] ?? []).contains(where: { $0.lowercased() == scheme }) else {
            LCDebugLog.record("host rejected target metadata mismatch", category: "GuestURL")
            throw LCPluginError("未找到目标应用或数据容器。")
        }
        // Deliver only to an existing window; never enter runApp's signing or launch fallback.
        guard await app.bringExistingMultitaskWindowIfNeeded(dataUUID: container, urlScheme: url.absoluteString) else {
            LCDebugLog.record("host rejected missing window", category: "GuestURL")
            throw LCPluginError("目标应用窗口已关闭，请先手动打开后重试。")
        }
        LCDebugLog.record("host delivered to existing window", category: "GuestURL")
    }
}
