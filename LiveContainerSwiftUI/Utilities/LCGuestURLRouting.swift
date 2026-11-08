import Foundation

enum LCGuestURLRouting {
    @MainActor static func open(_ url: URL, delegate: LCAppModelDelegate) async throws {
        guard let request = LCGuestURLRouter.request(for: url),
              let bundle = request["bundle-name"] as? String,
              let container = request["container-folder-name"] as? String,
              let original = request["url"] as? String, let scheme = URL(string: original)?.scheme?.lowercased() else {
            throw LCPluginError("应用间跳转请求无效或已过期，请返回原应用重试。")
        }
        let model = DataManager.shared.model
        try model.reloadApps()
        let apps = model.apps + (LCUtils.appGroupUserDefault.bool(forKey: "LCStrictHiding") ? [] : model.hiddenApps)
        guard let app = apps.first(where: { $0.appInfo.relativeBundlePath == bundle }),
              container.isEmpty || app.appInfo.containers.contains(where: { $0.folderName == container }),
              (app.appInfo.urlSchemes() as? [String] ?? []).contains(where: { $0.lowercased() == scheme }) else {
            throw LCPluginError("未找到目标应用或数据容器。")
        }
        if app.appInfo.isLocked || app.appInfo.isHidden {
            guard try await LCUtils.authenticateUser() else { return }
        }
        // Preserve the URL envelope until the target's base hooks can restore the callback context.
        let multitask = request["multitask"] as? String == "1" || MultitaskManager.isUsing(container: container)
        if multitask && app.appInfo.defaultClassicMode != 0 {
            throw LCPluginError("目标应用使用经典模式，请准备一个空闲 LC2/LC3 承接跳转。")
        }
        if !multitask && MultitaskManager.isMultitasking() {
            throw LCPluginError("目标 LC 正承载多任务应用，请准备一个空闲 LC2/LC3，当前应用会保持运行。")
        }
        app.delegate = delegate
        try await app.runApp(multitask: multitask, containerFolderName: container.isEmpty ? nil : container, urlStr: url.absoluteString)
    }
}
