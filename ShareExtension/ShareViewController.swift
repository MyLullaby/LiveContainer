import Combine
import LocalAuthentication
import SwiftUI
import UniformTypeIdentifiers
import UIKit

final class SharePayload: ObservableObject {
    enum Kind {
        case loading
        case url(URL)
        case files([URL])
        case empty
        case failed(String)
    }

    @Published var kind: Kind = .loading

    var sharedURL: URL? {
        if case .url(let url) = kind {
            return url
        }
        return nil
    }
}

struct ShareContainer: Identifiable, Hashable {
    let id: String
    let folderName: String
    let name: String
    let isShared: Bool
    let containerURL: URL
    let bookmarkData: Data?
}

struct ShareApp: Identifiable, Hashable {
    let id: String
    let relativeBundlePath: String
    let displayName: String
    let bundleIdentifier: String
    let isShared: Bool
    let isHidden: Bool
    let isLocked: Bool
    let isJITNeeded: Bool
    let containers: [ShareContainer]
    let iconURL: URL?

    var primaryContainer: ShareContainer? {
        containers.first
    }
}

struct ShareLaunchItem: Identifiable, Hashable {
    let app: ShareApp
    let container: ShareContainer

    var id: String {
        "\(app.id)|\(container.id)"
    }
}

@MainActor
final class ShareExtensionViewModel: ObservableObject {
    @Published var payload = SharePayload()
    @Published var visibleApps: [ShareApp] = []
    @Published var hiddenApps: [ShareApp] = []
    @Published var recommendedBundleIDs: [String] = []
    @Published var hiddenUnlocked = false
    @Published var isLaunching = false
    @Published var errorMessage: String?

    private var allApps: [ShareApp] = []
    private var sharedDefaults: UserDefaults?
    private var privateDocURL: URL?
    private var privateDocAccessing = false
    private var appGroupRootURL: URL?
    private weak var currentContext: NSExtensionContext?

    init() {
        self.sharedDefaults = UserDefaults(suiteName: LCSharedUtils.appGroupID())
        self.appGroupRootURL = LCSharedUtils.appGroupPath()?.appendingPathComponent("LiveContainer")
        self.privateDocURL = Self.resolvePrivateDocURL(sharedDefaults: sharedDefaults)
        self.privateDocAccessing = privateDocURL != nil
        reloadApps()
    }

    deinit {
        if privateDocAccessing {
            privateDocURL?.stopAccessingSecurityScopedResource()
        }
    }

    func loadPayload(from context: NSExtensionContext?) {
        if let context {
            currentContext = context
        }
        Task {
            do {
                let loaded = try await ShareExtensionItemLoader.load(from: context)
                await MainActor.run {
                    self.payload.kind = loaded
                }
                if let url = await MainActor.run(body: { self.payload.sharedURL }) {
                    await refreshRecommendation(for: url)
                } else {
                    await MainActor.run {
                        self.recommendedBundleIDs = []
                    }
                }
            } catch {
                await MainActor.run {
                    self.payload.kind = .failed(error.localizedDescription)
                }
            }
        }
    }

    func cancelRequest() {
        currentContext?.cancelRequest(withError: ShareExtensionError("Cancelled"))
    }

    func unlockHiddenApps() async {
        do {
            guard try await Self.authenticateUser() else {
                return
            }
            hiddenUnlocked = true
            rebuildVisibleApps()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func launch(app: ShareApp, context: NSExtensionContext?) async {
        guard let container = app.primaryContainer else {
            errorMessage = "No container is available."
            return
        }
        await launch(app: app, container: container, context: context)
    }

    func launch(app: ShareApp, container: ShareContainer, context: NSExtensionContext?) async {
        if isLaunching {
            return
        }
        isLaunching = true
        defer { isLaunching = false }

        do {
            if (app.isLocked || app.isHidden) && !hiddenUnlocked {
                guard try await Self.authenticateUser() else {
                    return
                }
            }

            let item = ShareLaunchItem(app: app, container: container)
            let launchURLString = try preparePayloadForLaunch(item)
            guard let launchURL = buildLaunchURL(for: item, launchURLString: launchURLString) else {
                throw ShareExtensionError("Unable to build launch URL.")
            }

            LCShareExtensionLauncher.openURL(fromShareExtension: launchURL)
            (context ?? currentContext)?.completeRequest(returningItems: nil, completionHandler: nil)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func recommendedApps() -> [ShareApp] {
        let candidates = hiddenUnlocked ? visibleApps + hiddenApps : visibleApps
        guard !recommendedBundleIDs.isEmpty else {
            return []
        }

        var rank: [String: Int] = [:]
        for bundleID in recommendedBundleIDs {
            let normalizedID = bundleID.lowercased()
            if rank[normalizedID] == nil {
                rank[normalizedID] = rank.count
            }
        }
        return candidates
            .filter { rank[$0.bundleIdentifier.lowercased()] != nil }
            .sorted { (rank[$0.bundleIdentifier.lowercased()] ?? Int.max) < (rank[$1.bundleIdentifier.lowercased()] ?? Int.max) }
    }

    func regularApps() -> [ShareApp] {
        visibleApps
    }

    func hiddenRegularApps() -> [ShareApp] {
        hiddenApps
    }

    func shouldShowHiddenUnlockButton() -> Bool {
        !hiddenUnlocked && !hiddenApps.isEmpty && !(sharedDefaults?.bool(forKey: "LCStrictHiding") ?? false)
    }

    private func reloadApps() {
        var apps: [ShareApp] = []
        if let privateDocURL {
            apps.append(contentsOf: loadApps(root: privateDocURL, isShared: false))
        }
        if let appGroupRootURL {
            apps.append(contentsOf: loadApps(root: appGroupRootURL, isShared: true))
        }

        allApps = apps
        rebuildVisibleApps()
    }

    private func rebuildVisibleApps() {
        let sorted = allApps.sorted {
            $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
        }

        visibleApps = sorted.filter { !$0.isHidden }
        hiddenApps = sorted.filter { $0.isHidden }
    }

    private func loadApps(root: URL, isShared: Bool) -> [ShareApp] {
        let applicationsURL = root.appendingPathComponent("Applications")
        guard let appDirs = try? FileManager.default.contentsOfDirectory(at: applicationsURL, includingPropertiesForKeys: nil) else {
            return []
        }

        return appDirs.compactMap { appURL in
            guard appURL.pathExtension == "app" else {
                return nil
            }
            return loadApp(appURL: appURL, root: root, isShared: isShared)
        }
    }

    private func loadApp(appURL: URL, root: URL, isShared: Bool) -> ShareApp? {
        guard
            let infoPlist = NSDictionary(contentsOf: appURL.appendingPathComponent("Info.plist")) as? [String: Any]
        else {
            return nil
        }
        let appInfo = (NSDictionary(contentsOf: appURL.appendingPathComponent("LCAppInfo.plist")) as? [String: Any]) ?? [:]
        let relativeBundlePath = appURL.lastPathComponent
        let displayName = (infoPlist["CFBundleDisplayName"] as? String)
            ?? (infoPlist["CFBundleName"] as? String)
            ?? (infoPlist["CFBundleExecutable"] as? String)
            ?? relativeBundlePath
        let bundleIdentifier: String
        if appInfo["doUseLCBundleId"] as? Bool == true, let original = appInfo["LCOrignalBundleIdentifier"] as? String {
            bundleIdentifier = original
        } else {
            bundleIdentifier = (infoPlist["CFBundleIdentifier"] as? String) ?? "Unknown"
        }

        let containers = loadContainers(appInfo: appInfo, root: root, isShared: isShared)
        let usableContainers = containers.isEmpty ? fallbackContainers(appInfo: appInfo, root: root, isShared: isShared) : containers
        guard !usableContainers.isEmpty else {
            return nil
        }

        let iconURL = iconURL(for: appURL)
        return ShareApp(
            id: "\(isShared ? "shared" : "private")|\(relativeBundlePath)",
            relativeBundlePath: relativeBundlePath,
            displayName: displayName,
            bundleIdentifier: bundleIdentifier,
            isShared: isShared,
            isHidden: appInfo["isHidden"] as? Bool ?? false,
            isLocked: appInfo["isLocked"] as? Bool ?? false,
            isJITNeeded: appInfo["isJITNeeded"] as? Bool ?? false,
            containers: usableContainers,
            iconURL: iconURL
        )
    }

    private func iconURL(for appURL: URL) -> URL? {
        let lightIconURL = appURL.appendingPathComponent("LCAppIconLight.png")
        let darkIconURL = appURL.appendingPathComponent("LCAppIconDark.png")

        let preferredIconURL: URL
        let fallbackIconURL: URL
        if #available(iOS 18.0, *), sharedDefaults?.bool(forKey: "darkModeIcon") == true {
            preferredIconURL = darkIconURL
            fallbackIconURL = lightIconURL
        } else {
            preferredIconURL = lightIconURL
            fallbackIconURL = darkIconURL
        }

        if FileManager.default.fileExists(atPath: preferredIconURL.path) {
            return preferredIconURL
        }
        if FileManager.default.fileExists(atPath: fallbackIconURL.path) {
            return fallbackIconURL
        }
        return nil
    }

    private func loadContainers(appInfo: [String: Any], root: URL, isShared: Bool) -> [ShareContainer] {
        guard let containerInfo = appInfo["LCContainers"] as? [[String: Any]] else {
            return []
        }
        return containerInfo.compactMap { dict in
            guard let folderName = dict["folderName"] as? String else {
                return nil
            }
            let name = (dict["name"] as? String) ?? folderName
            let bookmarkData = dict["bookmarkData"] as? Data
            let resolvedURL = bookmarkData.flatMap { Self.resolveBookmarkURL($0) }
            let containerURL = resolvedURL ?? root.appendingPathComponent("Data/Application").appendingPathComponent(folderName)
            return ShareContainer(
                id: "\(isShared ? "shared" : "private")|\(folderName)",
                folderName: folderName,
                name: name,
                isShared: isShared,
                containerURL: containerURL,
                bookmarkData: bookmarkData
            )
        }
    }

    private func fallbackContainers(appInfo: [String: Any], root: URL, isShared: Bool) -> [ShareContainer] {
        guard let folderName = appInfo["LCDataUUID"] as? String else {
            return []
        }
        return [
            ShareContainer(
                id: "\(isShared ? "shared" : "private")|\(folderName)",
                folderName: folderName,
                name: folderName,
                isShared: isShared,
                containerURL: root.appendingPathComponent("Data/Application").appendingPathComponent(folderName),
                bookmarkData: nil
            )
        ]
    }

    private func preparePayloadForLaunch(_ item: ShareLaunchItem) throws -> String? {
        switch payload.kind {
        case .url(let url):
            return url.absoluteString
        case .files(let fileURLs):
            let inboxURL = item.container.containerURL.appendingPathComponent("Inbox")
            let accessed = item.container.containerURL.startAccessingSecurityScopedResource()
            defer {
                if accessed {
                    item.container.containerURL.stopAccessingSecurityScopedResource()
                }
            }

            try FileManager.default.createDirectory(at: inboxURL, withIntermediateDirectories: true)
            var copiedFiles: [URL] = []
            for fileURL in fileURLs {
                let destination = uniqueDestinationURL(in: inboxURL, fileName: fileURL.lastPathComponent)
                try FileManager.default.copyItem(at: fileURL, to: destination)
                copiedFiles.append(destination)
            }
            return copiedFiles.first?.absoluteString
        case .empty:
            return nil
        case .loading:
            throw ShareExtensionError("The shared item is still loading.")
        case .failed(let message):
            throw ShareExtensionError(message)
        }
    }

    private func uniqueDestinationURL(in directory: URL, fileName: String) -> URL {
        let base = (fileName as NSString).deletingPathExtension
        let ext = (fileName as NSString).pathExtension
        var candidate = directory.appendingPathComponent(fileName)
        var index = 1
        while FileManager.default.fileExists(atPath: candidate.path) {
            let nextName = ext.isEmpty ? "\(base)-\(index)" : "\(base)-\(index).\(ext)"
            candidate = directory.appendingPathComponent(nextName)
            index += 1
        }
        return candidate
    }

    private func buildLaunchURL(for item: ShareLaunchItem, launchURLString: String?) -> URL? {
        var schemeToLaunch: String?
        var newLaunch = false

        if var runningLC = LCSharedUtils.getContainerUsingLCScheme(withFolderName: item.container.folderName) {
            if runningLC.hasSuffix("liveprocess") {
                runningLC = (runningLC as NSString).deletingPathExtension
            }
            schemeToLaunch = runningLC
        } else {
            newLaunch = true
            schemeToLaunch = item.app.isShared ? firstFreeInstalledLC() : "livecontainer"
        }

        guard let schemeToLaunch else {
            return fallbackLaunchURL(for: item, launchURLString: launchURLString)
        }

        if newLaunch && !item.app.isHidden && !item.app.isLocked && !item.app.isJITNeeded {
            sharedDefaults?.set(schemeToLaunch, forKey: "LCLaunchExtensionScheme")
            sharedDefaults?.set(item.app.relativeBundlePath, forKey: "LCLaunchExtensionBundleID")
            sharedDefaults?.set(item.container.folderName, forKey: "LCLaunchExtensionContainerName")
            if let launchURLString {
                sharedDefaults?.set(launchURLString, forKey: "LCLaunchExtensionLaunchURL")
            }
            sharedDefaults?.set(Date(), forKey: "LCLaunchExtensionLaunchDate")
        }

        var components = URLComponents()
        components.scheme = schemeToLaunch
        components.host = "livecontainer-launch"
        var queryItems = [
            URLQueryItem(name: "bundle-name", value: item.app.relativeBundlePath),
            URLQueryItem(name: "container-folder-name", value: item.container.folderName)
        ]
        if let launchURLString {
            queryItems.append(URLQueryItem(name: "open-url", value: Data(launchURLString.utf8).base64EncodedString()))
        }
        components.queryItems = queryItems
        return components.url
    }

    private func fallbackLaunchURL(for item: ShareLaunchItem, launchURLString: String?) -> URL? {
        var components = URLComponents()
        components.scheme = "livecontainer"
        components.host = "livecontainer-launch"
        var queryItems = [
            URLQueryItem(name: "bundle-name", value: item.app.relativeBundlePath),
            URLQueryItem(name: "container-folder-name", value: item.container.folderName)
        ]
        if let launchURLString {
            queryItems.append(URLQueryItem(name: "open-url", value: Data(launchURLString.utf8).base64EncodedString()))
        }
        components.queryItems = queryItems
        return components.url
    }

    private func firstFreeInstalledLC() -> String? {
        for scheme in LCSharedUtils.lcUrlSchemes() {
            guard
                let url = URL(string: "\(scheme)://"),
                LCShareExtensionLauncher.canOpenURL(fromShareExtension: url)
            else {
                continue
            }
            if LCSharedUtils.isLCScheme(inUse: scheme) {
                continue
            }
            return scheme
        }
        return nil
    }

    private func refreshRecommendation(for url: URL) async {
        guard url.scheme?.lowercased() == "https", let host = url.host?.lowercased() else {
            recommendedBundleIDs = []
            return
        }
        let bundleIDs = await AssociatedDomainResolver.bundleIDs(for: host)
        await MainActor.run {
            self.recommendedBundleIDs = bundleIDs
        }
    }

    private static func resolvePrivateDocURL(sharedDefaults: UserDefaults?) -> URL? {
        guard let bookmarkData = sharedDefaults?.data(forKey: "LCLaunchExtensionPrivateDocBookmark") else {
            return nil
        }
        guard let url = resolveBookmarkURL(bookmarkData) else {
            sharedDefaults?.set(nil, forKey: "LCLaunchExtensionPrivateDocBookmark")
            return nil
        }
        _ = url.startAccessingSecurityScopedResource()
        return url
    }

    private static func resolveBookmarkURL(_ bookmarkData: Data) -> URL? {
        do {
            var isStale = false
            return try URL(resolvingBookmarkData: bookmarkData, bookmarkDataIsStale: &isStale)
        } catch {
            return nil
        }
    }

    private static func authenticateUser() async throws -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            if let error = error as? LAError, error.code == .passcodeNotSet {
                return true
            }
            if let error {
                throw error
            }
            return false
        }

        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authentication is required to show hidden apps.") { success, evaluationError in
                if let evaluationError = evaluationError as? LAError, evaluationError.code == .userCancel || evaluationError.code == .appCancel {
                    continuation.resume(returning: false)
                } else if let evaluationError {
                    continuation.resume(throwing: evaluationError)
                } else {
                    continuation.resume(returning: success)
                }
            }
        }
    }
}

struct ShareExtensionRootView: View {
    @ObservedObject var viewModel: ShareExtensionViewModel
    let extensionContext: NSExtensionContext?

    private let columns = [
        GridItem(.adaptive(minimum: 58, maximum: 70), spacing: 10)
    ]

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    let recommended = viewModel.recommendedApps()
                    suggestedSection(apps: recommended)

                    let regular = viewModel.regularApps()
                    let hiddenApps = viewModel.hiddenRegularApps()
                    let showHiddenUnlockButton = viewModel.shouldShowHiddenUnlockButton()

                    if regular.isEmpty && !showHiddenUnlockButton && !(viewModel.hiddenUnlocked && !hiddenApps.isEmpty) {
                        VStack(spacing: 8) {
                            Image(systemName: "app")
                                .font(.system(size: 28))
                            Text("No available apps")
                        }
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 32)
                    } else {
                        appGridSection(title: "Apps", apps: regular, includesHiddenUnlockButton: showHiddenUnlockButton)
                    }

                    if viewModel.hiddenUnlocked && !hiddenApps.isEmpty {
                        appGridSection(title: "Hidden Apps", apps: hiddenApps)
                    }
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 14)
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        viewModel.cancelRequest()
                    }
                }
            }
            .alert("Error", isPresented: Binding(
                get: { viewModel.errorMessage != nil },
                set: { if !$0 { viewModel.errorMessage = nil } }
            )) {
                Button("OK") { viewModel.errorMessage = nil }
            } message: {
                Text(viewModel.errorMessage ?? "")
            }
            .navigationTitle(Text("LiveContainer"))
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func suggestedSection(apps: [ShareApp]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Suggested")
                .font(.headline)
            LazyVGrid(columns: columns, alignment: .leading, spacing: 12) {
                if apps.isEmpty {
                    ShareSuggestedPlaceholderLabel()
                } else {
                    ForEach(apps) { app in
                        ShareAppGridEntry(app: app, viewModel: viewModel, extensionContext: extensionContext)
                    }
                }
            }
        }
    }

    private func appGridSection(title: String, apps: [ShareApp], includesHiddenUnlockButton: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.headline)
            LazyVGrid(columns: columns, alignment: .leading, spacing: 12) {
                ForEach(apps) { app in
                    ShareAppGridEntry(app: app, viewModel: viewModel, extensionContext: extensionContext)
                }
                if includesHiddenUnlockButton {
                    ShareHiddenUnlockGridEntry(viewModel: viewModel)
                }
            }
        }
    }
}

struct ShareSuggestedPlaceholderLabel: View {
    var body: some View {
        VStack(spacing: 7) {
            RoundedRectangle(cornerRadius: 52 * 0.2667, style: .continuous)
                .fill(Color(.secondarySystemBackground))
                .overlay {
                    Image(systemName: "app.dashed")
                        .font(.system(size: 26))
                        .foregroundStyle(.tertiary)
                }
                .frame(width: 52, height: 52)
            Text(" ")
                .font(.caption)
                .frame(width: 64, height: 32, alignment: .top)
        }
        .frame(width: 64)
        .accessibilityHidden(true)
    }
}

struct ShareHiddenUnlockGridEntry: View {
    @ObservedObject var viewModel: ShareExtensionViewModel

    var body: some View {
        Button {
            Task { await viewModel.unlockHiddenApps() }
        } label: {
            VStack(spacing: 7) {
                Image(systemName: "ellipsis")
                    .font(.system(size: 26, weight: .semibold))
                    .frame(width: 52, height: 52)
                    .background(Color(.secondarySystemBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 52 * 0.2667, style: .continuous))
                Text(" ")
                    .font(.caption)
                    .lineLimit(1)
                    .foregroundStyle(.primary)
                    .frame(width: 64, height: 32, alignment: .top)
            }
            .frame(width: 64)
        }
        .buttonStyle(.plain)
    }
}

struct ShareAppGridEntry: View {
    let app: ShareApp
    @ObservedObject var viewModel: ShareExtensionViewModel
    let extensionContext: NSExtensionContext?

    var body: some View {
        if app.containers.count > 1 {
            NavigationLink {
                ShareContainerSelectionView(app: app, viewModel: viewModel, extensionContext: extensionContext)
            } label: {
                ShareAppGridLabel(app: app)
            }
            .buttonStyle(.plain)
        } else {
            Button {
                Task { await viewModel.launch(app: app, context: extensionContext) }
            } label: {
                ShareAppGridLabel(app: app)
            }
            .buttonStyle(.plain)
        }
    }
}

struct ShareAppGridLabel: View {
    let app: ShareApp

    var body: some View {
        VStack(spacing: 7) {
            ShareAppIconView(iconURL: app.iconURL)
                .frame(width: 52, height: 52)
            Text(app.displayName)
                .font(.caption)
                .multilineTextAlignment(.center)
                .lineLimit(2)
                .foregroundStyle(.primary)
                .frame(width: 64, height: 32, alignment: .top)
        }
        .frame(width: 64)
    }
}

struct ShareAppIconView: View {
    let iconURL: URL?

    var body: some View {
        GeometryReader { geometry in
            if let iconURL, let image = UIImage(contentsOfFile: iconURL.path) {
                Image(uiImage: image)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .clipShape(RoundedRectangle(cornerRadius: geometry.size.width * 0.2667, style: .continuous))
            } else {
                Image(systemName: "app")
                    .font(.system(size: geometry.size.width * 0.56))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .foregroundStyle(.secondary)
                    .background(Color(.secondarySystemBackground))
                    .clipShape(RoundedRectangle(cornerRadius: geometry.size.width * 0.2667, style: .continuous))
            }
        }
    }
}

struct ShareContainerSelectionView: View {
    let app: ShareApp
    @ObservedObject var viewModel: ShareExtensionViewModel
    let extensionContext: NSExtensionContext?

    var body: some View {
        List {
            ForEach(app.containers) { container in
                Button {
                    Task { await viewModel.launch(app: app, container: container, context: extensionContext) }
                } label: {
                    HStack(spacing: 12) {
                        ShareAppIconView(iconURL: app.iconURL)
                            .frame(width: 36, height: 36)
                        Text(container.name)
                            .foregroundStyle(.primary)
                        Spacer()
                    }
                }
            }
        }
        .navigationTitle(app.displayName)
    }
}

final class ShareExtensionHandler: UIViewController {
    private let viewModel = ShareExtensionViewModel()
    private var host: UIHostingController<ShareExtensionRootView>?

    override func viewDidLoad() {
        super.viewDidLoad()
        let root = ShareExtensionRootView(viewModel: viewModel, extensionContext: extensionContext)
        let host = UIHostingController(rootView: root)
        self.host = host
        addChild(host)
        view.addSubview(host.view)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        host.didMove(toParent: self)
        viewModel.loadPayload(from: extensionContext)
    }

    override func beginRequest(with context: NSExtensionContext) {
        viewModel.loadPayload(from: context)
    }
}

enum ShareExtensionItemLoader {
    static func load(from context: NSExtensionContext?) async throws -> SharePayload.Kind {
        guard let items = context?.inputItems as? [NSExtensionItem] else {
            return .empty
        }

        let providers = items.flatMap { $0.attachments ?? [] }
        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(UTType.url.identifier) {
                let item = try await loadItem(provider: provider, typeIdentifier: UTType.url.identifier)
                if let url = item as? URL {
                    return .url(url)
                }
                if let url = item as? NSURL {
                    return .url(url as URL)
                }
                if let data = item as? Data, let string = String(data: data, encoding: .utf8), let url = URL(string: string) {
                    return .url(url)
                }
                if let string = item as? String, let url = URL(string: string) {
                    return .url(url)
                }
            }
        }

        var fileURLs: [URL] = []
        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
                let item = try await loadItem(provider: provider, typeIdentifier: UTType.fileURL.identifier)
                if let url = item as? URL {
                    fileURLs.append(try copyToTemporaryShareLocation(url))
                } else if let url = item as? NSURL {
                    fileURLs.append(try copyToTemporaryShareLocation(url as URL))
                }
                continue
            }

            if let typeIdentifier = provider.registeredTypeIdentifiers.first {
                if let url = try await loadFileRepresentation(provider: provider, typeIdentifier: typeIdentifier) {
                    fileURLs.append(try copyToTemporaryShareLocation(url))
                }
            }
        }

        return fileURLs.isEmpty ? .empty : .files(fileURLs)
    }

    private static func loadItem(provider: NSItemProvider, typeIdentifier: String) async throws -> NSSecureCoding {
        try await withCheckedThrowingContinuation { continuation in
            provider.loadItem(forTypeIdentifier: typeIdentifier, options: nil) { item, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let item else {
                    continuation.resume(throwing: ShareExtensionError("Unable to read shared item."))
                    return
                }
                continuation.resume(returning: item)
            }
        }
    }

    private static func loadFileRepresentation(provider: NSItemProvider, typeIdentifier: String) async throws -> URL? {
        try await withCheckedThrowingContinuation { continuation in
            provider.loadFileRepresentation(forTypeIdentifier: typeIdentifier) { url, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: url)
            }
        }
    }

    private static func copyToTemporaryShareLocation(_ sourceURL: URL) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("LiveContainerShareExtension", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let destination = directory.appendingPathComponent(sourceURL.lastPathComponent.isEmpty ? UUID().uuidString : sourceURL.lastPathComponent)
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }

        let accessing = sourceURL.startAccessingSecurityScopedResource()
        defer {
            if accessing {
                sourceURL.stopAccessingSecurityScopedResource()
            }
        }
        try FileManager.default.copyItem(at: sourceURL, to: destination)
        return destination
    }
}

enum AssociatedDomainResolver {
    static func bundleIDs(for host: String) async -> [String] {
        var hosts = [host]
        if host.hasPrefix("www.") {
            hosts.append(String(host.dropFirst(4)))
        }

        for host in hosts {
            let bundleIDs = await fetchBundleIDs(for: host)
            if !bundleIDs.isEmpty {
                return bundleIDs
            }
        }
        return []
    }

    private static func fetchBundleIDs(for host: String) async -> [String] {
        let urls = [
            URL(string: "https://\(host)/apple-app-site-association"),
            URL(string: "https://\(host)/.well-known/apple-app-site-association")
        ].compactMap { $0 }

        return await withTaskGroup(of: [String].self) { group in
            for url in urls {
                group.addTask {
                    await fetchBundleIDs(from: url)
                }
            }

            var result: [String] = []
            for await ids in group {
                for id in ids where !result.contains(id) {
                    result.append(id)
                }
            }
            return result
        }
    }

    private static func fetchBundleIDs(from url: URL) async -> [String] {
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            let association = try JSONDecoder().decode(SiteAssociation.self, from: data)
            return association.applinks?.details.flatMap { $0.bundleIDs } ?? []
        } catch {
            return []
        }
    }
}

struct SiteAssociation: Decodable {
    let applinks: AppLinks?
}

struct AppLinks: Decodable {
    let details: [SiteAssociationDetailItem]

    enum CodingKeys: String, CodingKey {
        case details
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let array = try? container.decode([SiteAssociationDetailItem].self, forKey: .details) {
            details = array
            return
        }
        if let dictionary = try? container.decode([String: SiteAssociationDetailItem].self, forKey: .details) {
            details = dictionary.map { appID, item in
                var item = item
                if item.appID == nil {
                    item.appID = appID
                }
                return item
            }
            return
        }
        details = []
    }
}

struct SiteAssociationDetailItem: Decodable {
    var appID: String?
    let appIDs: [String]?

    var bundleIDs: [String] {
        var result: [String] = []
        if let appID {
            result.append(Self.bundleID(from: appID))
        }
        if let appIDs {
            result.append(contentsOf: appIDs.map(Self.bundleID(from:)))
        }
        return result.filter { !$0.isEmpty }
    }

    private static func bundleID(from appID: String) -> String {
        guard let dot = appID.firstIndex(of: ".") else {
            return ""
        }
        return String(appID[appID.index(after: dot)...])
    }
}

struct ShareExtensionError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? {
        message
    }
}
