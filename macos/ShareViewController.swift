import Cocoa
import UniformTypeIdentifiers

private final class DeviceGridView: NSView {
    override var isFlipped: Bool { true }
}
private final class DeviceCardButton: NSButton {
    override var isFlipped: Bool { true }
    let deviceIcon = NSImageView(frame: .zero)
    let deviceName = NSTextField(labelWithString: "")
    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        configureContents()
    }
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        configureContents()
    }
    private func configureContents() {
        title = ""
        isBordered = false
        deviceIcon.frame = NSRect(x: 33, y: 14, width: 44, height: 38)
        deviceIcon.imageScaling = .scaleProportionallyDown
        deviceName.frame = NSRect(x: 7, y: 66, width: 96, height: 22)
        deviceName.alignment = .center
        deviceName.font = .systemFont(ofSize: 12, weight: .medium)
        deviceName.lineBreakMode = .byTruncatingTail
        addSubview(deviceIcon)
        addSubview(deviceName)
    }
    override func hitTest(_ point: NSPoint) -> NSView? {
        // The whole card, including its icon and label, selects the device.
        super.hitTest(point) == nil ? nil : self
    }
}
private struct ShareDeviceChoice {
    let endpoint: String
    let name: String
    let type: Int
    var symbol: String {
        switch type { case 1: return "iphone"; case 2: return "laptopcomputer"; case 3: return "ipad"; default: return "desktopcomputer" }
    }
    var kind: String {
        switch type { case 1: return "手机"; case 2: return "电脑"; case 3: return "平板"; default: return "设备" }
    }
}

@objc(ShareViewController)
final class ShareViewController: NSViewController {
    private let label = NSTextField(wrappingLabelWithString: "准备分享文件…")
    private let button = NSButton(title: "取消", target: nil, action: nil)
    private let devices = DeviceGridView(frame: .zero)
    private let deviceScroll = NSScrollView(frame: .zero)
    private let emptyDevices = NSTextField(wrappingLabelWithString: "正在搜索可接收设备…")
    private var choices: [ShareDeviceChoice] = []
    private var selectedEndpoint: String?
    private var deviceButtons: [DeviceCardButton] = []
    private let send = NSButton(title: "发送", target: nil, action: nil)
    private var preparedNames: [String] = []
    private var submitted = false
    private var catalogueUpdated = Date.distantPast
    private var catalogueSignature = ""
    private var directory: URL?
    private var timer: Timer?
    private var started = Date()
    private var finished = false
    private var loading = false
    private var total: Int64 = 0
    private let limit: Int64 = 8 * 1024 * 1024 * 1024

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: 380))
        let icon = NSImageView(frame: NSRect(x: 24, y: 320, width: 36, height: 36))
        if let path = Bundle.main.path(forResource: "Clip", ofType: "icns") { icon.image = NSImage(contentsOfFile: path) }
        let title = NSTextField(labelWithString: "Clip 分享")
        title.font = .boldSystemFont(ofSize: 19)
        title.frame = NSRect(x: 74, y: 325, width: 260, height: 27)
        label.frame = NSRect(x: 24, y: 254, width: 352, height: 56)
        label.font = .systemFont(ofSize: 14)
        let deviceHeading = NSTextField(labelWithString: "选择接收设备")
        deviceHeading.frame = NSRect(x: 24, y: 230, width: 352, height: 20)
        deviceHeading.font = .systemFont(ofSize: 12, weight: .medium)
        deviceScroll.frame = NSRect(x: 24, y: 94, width: 352, height: 128)
        deviceScroll.hasVerticalScroller = true
        deviceScroll.autohidesScrollers = true
        deviceScroll.drawsBackground = false
        devices.frame = NSRect(x: 0, y: 0, width: 352, height: 128)
        deviceScroll.documentView = devices
        emptyDevices.frame = NSRect(x: 8, y: 34, width: 332, height: 60)
        emptyDevices.alignment = .center
        emptyDevices.font = .systemFont(ofSize: 12)
        emptyDevices.textColor = .secondaryLabelColor
        devices.addSubview(emptyDevices)
        send.frame = NSRect(x: 194, y: 16, width: 86, height: 30)
        send.bezelStyle = .rounded
        send.isEnabled = false
        send.target = self
        send.action = #selector(sendFiles)
        let note = NSTextField(wrappingLabelWithString: "选择设备并点击发送后，才会发起文件传输。")
        note.frame = NSRect(x: 24, y: 51, width: 352, height: 32)
        note.font = .systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        button.frame = NSRect(x: 290, y: 16, width: 86, height: 30)
        button.bezelStyle = .rounded
        button.target = self
        button.action = #selector(close)
        let refresh = NSButton(title: "刷新设备", target: self, action: #selector(refreshDevices))
        refresh.bezelStyle = .rounded
        refresh.frame = NSRect(x: 24, y: 16, width: 90, height: 30)
        [icon, title, label, deviceHeading, deviceScroll, send, note, button, refresh].forEach { view.addSubview($0) }
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
            launchClient()
            refreshDevices()
            timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in self?.poll() }
            load(providers, index: 0, names: [])
        } catch { fail("无法准备文件：\(error.localizedDescription)") }
    }
    private func load(_ providers: [NSItemProvider], index: Int, names: [String]) {
        guard !finished, let directory = directory else { return }
        if index == providers.count {
            preparedNames = names
            label.stringValue = "已准备 \(names.count) 个文件 · 请选择接收设备。"
            deviceChanged()
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
    private func launchClient() {
        let app = Bundle.main.bundleURL.deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let config = NSWorkspace.OpenConfiguration()
        config.activates = false
        NSWorkspace.shared.openApplication(at: app, configuration: config) { [weak self] _, error in
            if let error = error { DispatchQueue.main.async { self?.fail("无法启动 Clip：\(error.localizedDescription)") } }
        }
    }
    @objc private func refreshDevices() {
        guard !submitted, let directory = directory else { return }
        try? Data().write(to: directory.deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("refresh-devices"), options: .atomic)
        readDevices()
    }
    private func readDevices() {
        guard !submitted, let directory = directory else { return }
        let path = directory.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("devices.json")
        var entries: [[String: Any]] = []
        if let data = try? Data(contentsOf: path),
           let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
           let updated = (json["updated"] as? NSNumber)?.doubleValue,
           Date().timeIntervalSince1970 - updated < 45 {
            catalogueUpdated = Date(timeIntervalSince1970: updated)
            entries = json["devices"] as? [[String: Any]] ?? []
        }
        let signature = entries.map { "\($0["endpoint"] ?? ""): \($0["name"] ?? ""): \($0["device_type"] ?? 1)" }.joined(separator: "|")
        if signature != catalogueSignature || (choices.isEmpty && !entries.isEmpty) {
            choices = entries.compactMap { entry in
                guard let endpoint = entry["endpoint"] as? String, let name = entry["name"] as? String else { return nil }
                return ShareDeviceChoice(endpoint: endpoint, name: name, type: (entry["device_type"] as? NSNumber)?.intValue ?? 1)
            }
            if !choices.contains(where: { $0.endpoint == selectedEndpoint }) { selectedEndpoint = nil }
            renderDevices()
            catalogueSignature = signature
        }
        if entries.isEmpty { emptyDevices.stringValue = "未发现设备\n请解锁手机并开启互联，然后刷新。" }
        deviceChanged()
    }
    private func renderDevices() {
        deviceButtons.forEach { $0.removeFromSuperview() }
        deviceButtons.removeAll()
        emptyDevices.isHidden = !choices.isEmpty
        let rows = (choices.count + 2) / 3
        devices.frame.size = NSSize(width: 352, height: max(128, rows * 110))
        for (index, choice) in choices.enumerated() {
            let card = DeviceCardButton(frame: NSRect(x: (index % 3) * 118, y: (index / 3) * 110, width: 110, height: 100))
            card.target = self
            card.action = #selector(selectDevice(_:))
            card.tag = index
            card.deviceName.stringValue = choice.name
            card.deviceIcon.image = NSImage(systemSymbolName: choice.symbol, accessibilityDescription: choice.kind)?
                .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 32, weight: .regular))
            card.toolTip = choice.name
            card.setAccessibilityLabel("\(choice.name)，\(choice.kind)")
            card.wantsLayer = true
            card.layer?.cornerRadius = 12
            devices.addSubview(card)
            deviceButtons.append(card)
        }
        deviceChanged()
    }
    @objc private func selectDevice(_ sender: NSButton) {
        guard !submitted, !finished, choices.indices.contains(sender.tag) else { return }
        selectedEndpoint = choices[sender.tag].endpoint
        deviceChanged()
    }
    @objc private func deviceChanged() {
        send.isEnabled = !submitted && !finished && !preparedNames.isEmpty && selectedEndpoint != nil
        for (index, card) in deviceButtons.enumerated() {
            let selected = choices[index].endpoint == selectedEndpoint
            card.isEnabled = !submitted && !finished
            card.deviceIcon.contentTintColor = selected ? .controlAccentColor : .labelColor
            card.deviceName.textColor = selected ? .controlAccentColor : .labelColor
            card.layer?.backgroundColor = (selected ? NSColor.controlAccentColor.withAlphaComponent(0.10) : NSColor.controlBackgroundColor).cgColor
            card.layer?.borderColor = (selected ? NSColor.controlAccentColor : NSColor.separatorColor.withAlphaComponent(0.35)).cgColor
            card.layer?.borderWidth = selected ? 2 : 1
            card.setAccessibilityValue(selected ? "已选择" : "未选择")
        }
    }
    @objc private func sendFiles() {
        guard !submitted, let directory = directory,
              !preparedNames.isEmpty,
              let endpoint = selectedEndpoint else { return }
        guard Date().timeIntervalSince(catalogueUpdated) < 45 else {
            label.stringValue = "设备列表已过期，请刷新后重新选择。"
            refreshDevices()
            return
        }
        do {
            let request: [String: Any] = ["files": preparedNames, "target": endpoint]
            try JSONSerialization.data(withJSONObject: request).write(to: directory.appendingPathComponent("request.json"), options: .atomic)
            let ready = directory.deletingPathExtension().appendingPathExtension("ready")
            try FileManager.default.moveItem(at: directory, to: ready)
            self.directory = ready
            submitted = true
            started = Date()
            send.isEnabled = false
            deviceChanged()
            label.stringValue = "正在连接所选设备…\n尚未开始发送文件。"
        } catch { fail("无法提交分享：\(error.localizedDescription)") }
    }
    private func poll() {
        guard !finished, let directory = directory else { return }
        if !submitted { readDevices(); return }
        if let data = try? Data(contentsOf: directory.appendingPathComponent("status.json")),
           let status = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
           let state = status["state"] as? String {
            switch state {
            case "connecting": label.stringValue = "正在与所选设备建立分享通道…\n尚未收到手机的接收响应。"
            case "waiting": label.stringValue = "分享请求已发出，等待手机接受…\n如手机显示接收提示，请确认。"
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
            case "failed":
                let message = status["message"] as? String ?? "分享通道已断开，未收到接收完成确认。"
                fail("文件未发送完成：\(message)")
                return
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
        send.isEnabled = false
        deviceChanged()
        label.stringValue = message
        button.title = "关闭"
        cleanup()
    }
    #if SHARE_PREVIEW
    static func preview(iconPath: String) -> ShareViewController {
        let controller = ShareViewController()
        _ = controller.view
        controller.loading = true
        (controller.view.subviews.first as? NSImageView)?.image = NSImage(contentsOfFile: iconPath)
        controller.label.stringValue = "已准备 1 个文件 · 请选择接收设备。"
        controller.preparedNames = ["example.png"]
        controller.choices = [
            ShareDeviceChoice(endpoint: "192.0.2.1:1234", name: "小米手机", type: 1),
            ShareDeviceChoice(endpoint: "192.0.2.2:1234", name: "测试平板", type: 3),
            ShareDeviceChoice(endpoint: "192.0.2.3:1234", name: "测试电脑", type: 2),
        ]
        controller.renderDevices()
        precondition(controller.deviceButtons.count == 3)
        precondition(!controller.send.isEnabled, "Must choose a device before sending")
        controller.selectDevice(controller.deviceButtons[0])
        precondition(controller.send.isEnabled, "Selected device must enable Send")
        precondition(controller.selectedEndpoint == "192.0.2.1:1234")
        return controller
    }
    #endif
    @objc private func close() {
        timer?.invalidate()
        let success = finished && button.title == "完成"
        finished = true
        cleanup()
        if success { extensionContext?.completeRequest(returningItems: nil, completionHandler: nil) }
        else { extensionContext?.cancelRequest(withError: NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)) }
    }
}
