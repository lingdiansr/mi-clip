import Cocoa
import UniformTypeIdentifiers

@objc(ShareViewController)
final class ShareViewController: NSViewController {
    private let label = NSTextField(wrappingLabelWithString: "准备分享文件…")
    private let button = NSButton(title: "取消", target: nil, action: nil)
    private var directory: URL?
    private var timer: Timer?
    private var started = Date()
    private var finished = false
    private var loading = false
    private var total: Int64 = 0
    private let limit: Int64 = 8 * 1024 * 1024 * 1024

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: 150))
        label.frame = NSRect(x: 24, y: 60, width: 332, height: 66)
        label.font = .systemFont(ofSize: 14)
        button.frame = NSRect(x: 270, y: 16, width: 86, height: 30)
        button.bezelStyle = .rounded
        button.target = self
        button.action = #selector(close)
        view.addSubview(label)
        view.addSubview(button)
    }
    override func viewDidAppear() {
        super.viewDidAppear()
        guard !loading else { return }
        loading = true
        let providers = (extensionContext?.inputItems as? [NSExtensionItem] ?? [])
            .flatMap { $0.attachments ?? [] }
        guard !providers.isEmpty && providers.count <= 128 else {
            fail("请选择 1–128 个普通文件。"); return
        }
        do {
            let root = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/MiClip/Outbox", isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            // Recover disk space left by an interrupted extension host.
            let oldRequests = (try? FileManager.default.contentsOfDirectory(at: root,
                includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
            for old in oldRequests where ["ready", "loading"].contains(old.pathExtension) {
                if let date = try? old.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate,
                   Date().timeIntervalSince(date) > 86400 {
                    try? FileManager.default.removeItem(at: old)
                }
            }
            let staging = root.appendingPathComponent(UUID().uuidString + ".loading", isDirectory: true)
            try FileManager.default.createDirectory(at: staging.appendingPathComponent("files"), withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            directory = staging
            load(providers, index: 0, names: [])
        } catch { fail("无法准备文件：\(error.localizedDescription)") }
    }
    private func load(_ providers: [NSItemProvider], index: Int, names: [String]) {
        guard !finished, let directory = directory else { return }
        if index == providers.count {
            do {
                try JSONSerialization.data(withJSONObject: names).write(to: directory.appendingPathComponent("request.json"), options: .atomic)
                let ready = directory.deletingPathExtension().appendingPathExtension("ready")
                try FileManager.default.moveItem(at: directory, to: ready)
                self.directory = ready
                started = Date()
                label.stringValue = "等待 Clip 连接手机…\n请保持手机解锁并开启互联功能。"
                // macOS supports launching the containing app through NSWorkspace.
                let app = Bundle.main.bundleURL.deletingLastPathComponent()
                    .deletingLastPathComponent().deletingLastPathComponent()
                let config = NSWorkspace.OpenConfiguration()
                config.activates = false
                NSWorkspace.shared.openApplication(at: app, configuration: config) { _, _ in }
                timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in self?.poll() }
            } catch { fail("无法提交分享：\(error.localizedDescription)") }
            return
        }
        let provider = providers[index]
        let receive: (URL?, Error?) -> Void = { [weak self] url, error in
            guard let self = self else { return }
            do {
                guard let url = url, url.isFileURL else {
                    throw error ?? NSError(domain: "Clip", code: 1,
                        userInfo: [NSLocalizedDescriptionKey: "只支持普通文件，暂不支持文件夹或网页链接。"])
                }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                let info = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
                guard info.isRegularFile == true, info.isSymbolicLink != true else {
                    throw NSError(domain: "Clip", code: 2, userInfo: [NSLocalizedDescriptionKey: "请选择普通文件。"])
                }
                let size = Int64(info.fileSize ?? 0)
                guard self.total + size <= self.limit else {
                    throw NSError(domain: "Clip", code: 3, userInfo: [NSLocalizedDescriptionKey: "单次分享最多 8 GiB。"])
                }
                var name = url.lastPathComponent
                if names.contains(name) { name = "\(index + 1)-\(name)" }
                let destination = directory.appendingPathComponent("files").appendingPathComponent(name)
                try FileManager.default.copyItem(at: url, to: destination)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
                DispatchQueue.main.async {
                    guard !self.finished else { return }
                    self.total += size
                    self.load(providers, index: index + 1, names: names + [name])
                }
            } catch { DispatchQueue.main.async { self.fail("无法读取文件：\(error.localizedDescription)") } }
        }
        if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, error in
                let url: URL?
                if let value = item as? URL { url = value }
                else if let data = item as? Data { url = URL(dataRepresentation: data, relativeTo: nil) }
                else { url = nil }
                receive(url, error)
            }
        } else if let type = provider.registeredTypeIdentifiers.first(where: {
            UTType($0)?.conforms(to: .data) == true
        }) {
            provider.loadFileRepresentation(forTypeIdentifier: type, completionHandler: receive)
        } else { fail("此内容不是可发送的文件。") }
    }
    private func poll() {
        guard !finished, let directory = directory else { return }
        if let data = try? Data(contentsOf: directory.appendingPathComponent("status.json")),
           let status = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
           let state = status["state"] as? String {
            switch state {
            case "connecting": label.stringValue = "正在向手机发起分享…\n请在手机上确认接收。"
            case "waiting": label.stringValue = "等待手机接收文件…\n请在手机上确认。"
            case "sending":
                let sent = (status["sent"] as? NSNumber)?.int64Value ?? 0
                label.stringValue = "正在发送到手机 · \(total == 0 ? 100 : min(100, Int(Double(sent) / Double(total) * 100)))%\n传输完成后将由手机确认。"
            case "completed":
                timer?.invalidate()
                label.stringValue = "手机已确认接收完成。"
                button.title = "完成"
                finished = true
                cleanup()
                return
            case "failed": fail("文件分享未完成。请确认手机连接和接收提示后重试。")
            default: break
            }
        }
        if Date().timeIntervalSince(started) > 600 && !label.stringValue.hasPrefix("正在发送") { fail("分享超时，请检查 Clip 和手机的连接后重试。") }
        if Date().timeIntervalSince(started) > 60 && !FileManager.default.fileExists(atPath: directory.appendingPathComponent("status.json").path) {
            fail("未能连接手机。请启动 Clip，确认已登录并连接手机后重试。")
        }
    }
    override func viewDidDisappear() {
        super.viewDidDisappear()
        timer?.invalidate()
        finished = true
        cleanup()
    }
    private func cleanup() {
        if let directory = directory { try? FileManager.default.removeItem(at: directory) }
    }
    private func fail(_ message: String) {
        timer?.invalidate()
        finished = true
        label.stringValue = message
        button.title = "关闭"
        cleanup()
    }
    @objc private func close() {
        timer?.invalidate()
        let success = finished && button.title == "完成"
        finished = true
        cleanup()
        if success { extensionContext?.completeRequest(returningItems: nil, completionHandler: nil) }
        else { extensionContext?.cancelRequest(withError: NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)) }
    }
}
