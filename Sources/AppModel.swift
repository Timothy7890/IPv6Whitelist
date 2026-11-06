import AppKit
import Foundation
import Combine

@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()
    @Published var entries: [WhitelistEntry] = []
    @Published var isEnabled = false
    @Published var isBusy = false
    @Published var helperReady = false
    @Published var gatewayText = "正在检测…"
    @Published var statusText = "尚未启用路由管理"
    @Published var lastError: String? = nil
    @Published var routeStatus: [String: String] = [:]
    @Published var logLines: [String] = []
    @Published var broadDefaultGateway: String? = nil
    @Published var ipv6ProtectionText = "正在检查 IPv6 默认出口…"
    @Published var lastUpdatedText = "尚未检查"

    @Published private(set) var weChatEnabled = false
    @Published private(set) var weChatStatus = "自动维护已关闭"
    @Published private(set) var weChatError: String?
    @Published private(set) var weChatLastScan = ""
    @Published private(set) var ignoredWeChatCount = 0
    private var weChatSettings = WeChatDiscoverySettings()
    private var weChatSettingsWritable = true
    private var discoveryTimer: Timer?
    private var discoveryRunning = false
    private var nextDiscovery = Date.distantPast
    private var lastDiscoverySave = Date.distantPast
    private var syncingEntries = false
    private var syncAgain = false
    private var needsRouteSync = false
    private var discoveryURL: URL { dataDirectory.appendingPathComponent("wechat-discovery.json") }
    var automaticWeChatCount: Int { entries.filter(\.isWeChatAutomatic).count }
    private var effectiveAddresses: [String] {
        entries.filter { $0.enabled && (!$0.isWeChatAutomatic || weChatEnabled) }.map(\.address)
    }

    private let service = RouteService()
    private var timer: Timer?
    private var refreshing = false
    private var shuttingDown = false
    private var storeWritable = true
    private var lastStatus: HelperStatus?
    private let dataDirectory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/IPv6Whitelist", isDirectory: true)
    private var dataURL: URL { dataDirectory.appendingPathComponent("whitelist.json") }

    init() {
        loadEntries()
        loadDiscoverySettings()
        log("已载入 \(entries.count) 个 IPv6 地址；应用不会自动启用路由")
        timer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        discoveryTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.scanWeChat() }
        }
        refresh()
    }

    private func loadEntries() {
        if FileManager.default.fileExists(atPath: dataURL.path) {
            do {
                entries = try JSONDecoder().decode([WhitelistEntry].self, from: Data(contentsOf: dataURL))
                entries = normalized(entries)
            } catch {
                storeWritable = false
                lastError = "白名单文件无法读取，已保留原文件。请通过“打开数据目录”检查 whitelist.json。"
            }
        } else if let seed = Bundle.main.url(forResource: "initial-whitelist", withExtension: "json"),
                  let data = try? Data(contentsOf: seed),
                  let imported = try? JSONDecoder().decode([WhitelistEntry].self, from: data) {
            entries = normalized(imported)
            _ = saveEntries()
        }
    }

    private func normalized(_ values: [WhitelistEntry]) -> [WhitelistEntry] {
        var seen = Set<String>()
        return values.compactMap { entry in
            guard let address = canonicalIPv6(entry.address), seen.insert(address).inserted else { return nil }
            var entry = entry
            entry.address = address
            return entry
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    @discardableResult private func saveEntries() -> Bool {
        guard storeWritable else {
            lastError = "已有白名单文件损坏。为保护原数据，当前禁止覆盖保存。"
            return false
        }
        do {
            try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(entries).write(to: dataURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: dataURL.path)
            return true
        } catch {
            lastError = "保存白名单失败：\(error.localizedDescription)"
            return false
        }
    }

    func addEntry(address: String, name: String) -> String? {
        guard let canonical = canonicalIPv6(address) else {
            return "请输入单个 IPv6 地址。支持 /128；不支持 IPv4、其他网段、链路本地地址或接口后缀。"
        }
        guard entries.count < 256 else { return "白名单最多支持 256 个地址。" }
        guard !entries.contains(where: { $0.address == canonical }) else { return "这个 IPv6 已经在白名单中。" }
        let label = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let prior = entries
        entries.append(WhitelistEntry(address: canonical, name: label.isEmpty ? "手动添加" : label, sources: ["手动添加"]))
        entries = normalized(entries)
        guard saveEntries() else { entries = prior; return lastError }
        log("添加 \(label.isEmpty ? canonical : label)")
        syncEntries()
        return nil
    }

    func updateEntry(_ entry: WhitelistEntry) {
        guard let canonical = canonicalIPv6(entry.address) else {
            lastError = "IPv6 地址无效；只接受单个可路由 IPv6 主机地址。"
            return
        }
        guard !entries.contains(where: { $0.id != entry.id && $0.address == canonical }) else {
            lastError = "这个 IPv6 已存在于其他白名单条目。"
            return
        }
        guard let index = entries.firstIndex(where: { $0.id == entry.id }) else { return }
        let prior = entries
        var updated = entry
        updated.address = canonical
        if updated.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { updated.name = "未命名" }
        entries[index] = updated
        guard saveEntries() else { entries = prior; return }
        syncEntries()
    }

    func deleteEntry(_ entry: WhitelistEntry) {
        guard excludeFromDiscovery(entry.address) else { return }
        let prior = entries
        entries.removeAll { $0.id == entry.id }
        guard saveEntries() else { entries = prior; return }
        log("删除 \(entry.name)")
        syncEntries()
    }

    func importSSH() {
        guard !isBusy else { return }
        isBusy = true
        lastError = nil
        Task {
            let result = await Task.detached { SSHImporter.load() }.value
            let prior = entries
            var added = 0
            for incoming in result.entries {
                if let index = entries.firstIndex(where: { $0.address == incoming.address }) {
                    entries[index].sources = Array(Set(entries[index].sources + incoming.sources)).sorted()
                    entries[index].automaticSource = nil
                } else if entries.count < 256 {
                    entries.append(incoming)
                    added += 1
                }
            }
            entries = normalized(entries)
            if !saveEntries() { entries = prior }
            log("SSH 导入完成：发现 \(result.entries.count) 个地址，新增 \(added) 个")
            for warning in result.warnings { log("导入提示：\(warning)") }
            isBusy = false
            syncEntries()
        }
    }

    private func syncEntries() {
        needsRouteSync = true
        guard helperReady else { refresh(); return }
        if syncingEntries { syncAgain = true; return }
        syncingEntries = true
        Task {
            repeat {
                syncAgain = false
                let addresses = effectiveAddresses
                do {
                    let response = try await service.request(HelperRequest(command: "update", addresses: addresses))
                    accept(response)
                    if response.ok && addresses == effectiveAddresses { needsRouteSync = false }
                } catch { report(error.localizedDescription) }
            } while syncAgain && !shuttingDown
            syncingEntries = false
        }
    }

    func activate() {
        guard !isBusy else { return }
        guard !effectiveAddresses.isEmpty || weChatEnabled else { lastError = "请先启用至少一个白名单地址。"; return }
        isBusy = true
        lastError = nil
        statusText = "正在准备路由服务，请完成 macOS 管理员授权…"
        Task {
            do {
                try await ensureHelper()
                let response = try await service.request(HelperRequest(command: "enable", addresses: effectiveAddresses))
                accept(response)
                if response.ok { log("已启用白名单；每 3 秒自动检查 Wi-Fi 网关") }
                nextDiscovery = .distantPast
            } catch { report(error.localizedDescription) }
            isBusy = false
        }
    }

    func deactivate() {
        guard !isBusy else { return }
        isBusy = true
        Task {
            do {
                let response = try await service.request(HelperRequest(command: "disable"))
                accept(response)
                if response.ok { log("已停用并清理本应用管理的主机路由") }
            } catch { report(error.localizedDescription) }
            isBusy = false
        }
    }

    private func ensureHelper() async throws {
        if let response = try? await service.request(HelperRequest(command: "status")) {
            accept(response)
            return
        }
        guard let helper = Bundle.main.url(forAuxiliaryExecutable: "ipv6-route-helper") else {
            throw LocalServiceError.unavailable("应用缺少路由辅助程序，请使用完整的 .app 文件。")
        }
        // Authorization runs as root and macOS privacy protection may deny it
        // access to Documents/Downloads even though this app can read its bundle.
        // Stage only our signed executable in a private temporary directory.
        let stagingDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("IPv6Whitelist-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: stagingDirectory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: stagingDirectory) }
        let stagedHelper = stagingDirectory.appendingPathComponent("ipv6-route-helper")
        try FileManager.default.copyItem(at: helper, to: stagedHelper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stagedHelper.path)
        let uid = getuid()
        let target = "/Library/PrivilegedHelperTools/local.timo.ipv6-whitelist-helper"
        let script = """
        set -eu
        /usr/bin/codesign --verify --strict \(shellQuote(stagedHelper.path))
        if [ ! -d /Library/PrivilegedHelperTools ]; then
          /usr/bin/install -d -o root -g wheel -m 0755 /Library/PrivilegedHelperTools
        fi
        /usr/bin/install -S -o root -g wheel -m 0755 \(shellQuote(stagedHelper.path)) \(shellQuote(target))
        /usr/bin/codesign --verify --strict \(shellQuote(target))
        launch_log=$(/usr/bin/mktemp /private/var/run/ipv6-whitelist-launch.XXXXXX)
        trap '/bin/rm -f "$launch_log"' EXIT
        \(shellQuote(target)) --uid \(uid) >"$launch_log" 2>&1 </dev/null &
        helper_pid=$!
        attempt=0
        while [ "$attempt" -lt 50 ]; do
          /bin/sleep 0.1
          if ! /bin/kill -0 "$helper_pid" 2>/dev/null; then
            /bin/cat "$launch_log"
            exit 1
          fi
          if [ -S \(shellQuote(helperSocketPath(uid: uid))) ]; then exit 0; fi
          attempt=$((attempt + 1))
        done
        /bin/kill -TERM "$helper_pid" 2>/dev/null || true
        /bin/cat "$launch_log"
        /bin/echo '路由辅助程序启动超时'
        exit 1
        """
        let authorization = "do shell script \(appleScriptString(script)) with administrator privileges\n"
        let result = await Task.detached {
            LocalCommand.run("/usr/bin/osascript", ["-"], input: authorization, timeout: 180)
        }.value
        guard result.code == 0 else {
            let detail = result.output.contains("-128") ? "已取消管理员授权，路由管理未启用。" : "管理员授权或辅助程序启动失败：\(result.output.trimmingCharacters(in: .whitespacesAndNewlines))"
            throw LocalServiceError.unavailable(detail)
        }
        for _ in 0..<20 {
            if let response = try? await service.request(HelperRequest(command: "status")) {
                accept(response)
                return
            }
            try await Task.sleep(nanoseconds: 300_000_000)
        }
        throw LocalServiceError.unavailable("授权已完成，但路由服务没有启动。请查看应用日志并重试。")
    }

    func refresh() {
        guard !refreshing, !isBusy, !shuttingDown else { return }
        refreshing = true
        Task {
            if let response = try? await service.request(HelperRequest(command: "status")) {
                accept(response)
                if needsRouteSync && !syncingEntries { syncEntries() }
            } else {
                if helperReady && isEnabled { log("与路由服务失去联系；辅助程序会在心跳超时后清理路由") }
                helperReady = false
                isEnabled = false
                let status = await Task.detached { Self.readOnlyStatus() }.value
                display(status)
            }
            refreshing = false
        }
    }

    nonisolated private static func readOnlyStatus() -> HelperStatus {
        var status = HelperStatus()
        let table = LocalCommand.run("/usr/sbin/netstat", ["-rn", "-f", "inet6"]).output
        for line in table.split(separator: "\n") {
            let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard fields.count >= 4, fields[0] == "default", fields[3] == "en0" else { continue }
            if fields[2].contains("I") { status.wifiGateway = fields[1] }
            else { status.broadDefaults.append(RouteRecord(destination: fields[0], gateway: fields[1], flags: fields[2], interface: fields[3])) }
        }
        let query = LocalCommand.run("/sbin/route", ["-n", "get", "-inet6", "2606:4700:4700::1111"]).output
        for line in query.split(separator: "\n") {
            let fields = line.split(whereSeparator: \.isWhitespace)
            if fields.count >= 2 && fields[0] == "interface:" { status.defaultIPv6Interface = String(fields[1]) }
        }
        return status
    }

    private func accept(_ response: HelperResponse) {
        helperReady = true
        if let status = response.status { display(status) }
        if !response.ok { report(response.message) }
    }

    private func display(_ status: HelperStatus) {
        if let previous = lastStatus, previous.wifiGateway != status.wifiGateway {
            log(status.wifiGateway.map { "Wi-Fi 网关已变更：\($0)" } ?? "当前 Wi-Fi 未提供 IPv6 网关，暂停添加路由")
        }
        let firstConnection = lastStatus == nil
        lastStatus = status
        isEnabled = status.enabled
        if firstConnection && status.enabled { syncEntries() }
        gatewayText = status.wifiGateway ?? "未发现 IPv6 网关"
        let active = Set(status.activeRoutes.map(\.address))
        var nextRouteStatus: [String: String] = [:]
        for entry in entries {
            if !entry.enabled { nextRouteStatus[entry.address] = "未勾选" }
            else if entry.isWeChatAutomatic && !weChatEnabled { nextRouteStatus[entry.address] = "自动维护已暂停" }
            else if active.contains(entry.address) { nextRouteStatus[entry.address] = "直连中" }
            else if status.conflicts.contains(where: { $0.contains(entry.address) }) { nextRouteStatus[entry.address] = "路由冲突" }
            else if status.enabled && status.wifiGateway == nil { nextRouteStatus[entry.address] = "等待 IPv6" }
            else if status.enabled { nextRouteStatus[entry.address] = "待应用" }
            else { nextRouteStatus[entry.address] = "待启用" }
        }
        if nextRouteStatus != routeStatus { routeStatus = nextRouteStatus }
        if status.enabled {
            statusText = status.wifiGateway == nil ? "等待支持 IPv6 的 Wi-Fi" : "正在管理 \(status.activeRoutes.count) 条直连路由"
        } else { statusText = helperReady ? "管理已停用 · 路由服务就绪" : "尚未启用路由管理" }
        broadDefaultGateway = status.broadDefaults.first(where: { $0.flags.contains("S") })?.gateway
        if !status.broadDefaults.isEmpty {
            ipv6ProtectionText = "当前有 Wi-Fi 默认直连路由，白名单以外的 IPv6 也可能直连。"
        } else if let interface = status.defaultIPv6Interface, interface.hasPrefix("utun") {
            ipv6ProtectionText = "抽样公网 IPv6 路由指向 \(interface)。是否使用代理节点，仍需在 Shadowrocket 中确认规则与实际出口。"
        } else if let interface = status.defaultIPv6Interface {
            ipv6ProtectionText = "抽样公网 IPv6 当前指向 \(interface)，可能直接使用真实网络出口。"
        } else {
            ipv6ProtectionText = "未发现普通公网 IPv6 的可用路由。请先在 Shadowrocket 中配置完整 IPv6 接管；本应用不会代替代理。"
        }
        lastUpdatedText = DateFormatter.localizedString(from: Date(timeIntervalSince1970: status.updatedAt), dateStyle: .none, timeStyle: .medium)
        if let error = status.error, !error.isEmpty {
            if error != lastError { log(error) }
            lastError = error
        }
    }

    func removeBroadDefault() {
        guard let gateway = broadDefaultGateway, !isBusy else { return }
        let alert = NSAlert()
        alert.messageText = "移除 Wi-Fi 的 IPv6 默认直连路由？"
        alert.informativeText = "将移除经 \(gateway) 的静态、非接口限定默认路由，保留白名单主机路由和 Wi-Fi 原生路由。\n\n如果 Shadowrocket 尚未接管公网 IPv6，白名单以外的 IPv6 连接可能暂时不可用。这不会自动开启 IPv6 代理。"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "移除默认直连")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        isBusy = true
        lastError = nil
        Task {
            do {
                try await ensureHelper()
                let response = try await service.request(HelperRequest(command: "removeBroadDefault", gateway: gateway))
                accept(response)
                if response.ok { log("已移除指定 Wi-Fi 默认直连路由；请确认 Shadowrocket 的 IPv6 出口") }
            } catch { report(error.localizedDescription) }
            isBusy = false
        }
    }

    func openDataFolder() {
        try? FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true)
        NSWorkspace.shared.open(dataDirectory)
    }

    func copyDirectRules() {
        let rules = effectiveAddresses.map { "IP-CIDR,\($0)/128,DIRECT,no-resolve" }.joined(separator: "\n")
        guard !rules.isEmpty else { lastError = "请先勾选需要直连的地址。"; return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(rules, forType: .string)
        log("已复制 \(entries.filter(\.enabled).count) 条 Shadowrocket 直连规则，请放在其他可能命中的规则之前")
        let alert = NSAlert()
        alert.messageText = "直连规则已复制"
        alert.informativeText = "将这些规则粘贴到 Shadowrocket 当前配置的 [Rule] 区段顶部。使用系统 HTTP/HTTPS 代理的应用，也需要对应的 DIRECT 规则。\n\n这些规则只声明白名单直连，不会开启 IPv6 或保证其他流量经过代理。"
        alert.addButton(withTitle: "知道了")
        alert.runModal()
    }

    func shutdown() {
        shuttingDown = true
        timer?.invalidate()
        discoveryTimer?.invalidate()
        _ = saveEntries()
        if helperReady { _ = try? SocketClient.request(HelperRequest(command: "stop"), timeout: 8) }
    }

    private func report(_ message: String) {
        lastError = message
        log(message)
        if !helperReady { statusText = "尚未启用路由管理" }
    }

    func log(_ message: String) {
        let stamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        logLines.insert("\(stamp)  \(message)", at: 0)
        if logLines.count > 100 { logLines.removeLast(logLines.count - 100) }
    }
}


extension AppModel {
    private func loadDiscoverySettings() {
        guard FileManager.default.fileExists(atPath: discoveryURL.path) else { return }
        do {
            weChatSettings = try JSONDecoder().decode(WeChatDiscoverySettings.self, from: Data(contentsOf: discoveryURL))
            weChatEnabled = weChatSettings.enabled
            ignoredWeChatCount = weChatSettings.excludedAddresses.count
            weChatStatus = weChatEnabled ? "等待首次检查" : "自动维护已关闭"
        } catch {
            weChatSettingsWritable = false
            weChatError = "自动维护配置无法读取，已保留原文件并停用自动维护。"
        }
    }

    @discardableResult private func saveDiscoverySettings() -> Bool {
        guard weChatSettingsWritable else { return false }
        do {
            try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(weChatSettings).write(to: discoveryURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: discoveryURL.path)
            ignoredWeChatCount = weChatSettings.excludedAddresses.count
            return true
        } catch {
            weChatError = "自动维护配置保存失败：\(error.localizedDescription)"
            return false
        }
    }

    func setWeChatEnabled(_ enabled: Bool) {
        let prior = weChatSettings
        weChatSettings.enabled = enabled
        guard saveDiscoverySettings() else { weChatSettings = prior; return }
        weChatEnabled = enabled
        nextDiscovery = .distantPast
        weChatStatus = enabled ? "等待检查" : "已暂停；动态路由已请求撤销，缓存保留"
        log(enabled ? "开启微信 IPv6 自动维护" : "暂停微信自动维护，保留手动白名单")
        syncEntries()
        if enabled { scanWeChat() }
    }

    private func excludeFromDiscovery(_ address: String) -> Bool {
        let prior = weChatSettings
        weChatSettings.excludedAddresses.insert(address)
        guard saveDiscoverySettings() else { weChatSettings = prior; return false }
        return true
    }

    func resetWeChatExclusions() {
        let prior = weChatSettings
        weChatSettings.excludedAddresses = []
        guard saveDiscoverySettings() else { weChatSettings = prior; return }
        nextDiscovery = .distantPast
        log("已恢复对手动移除地址的自动发现；未勾选的条目仍保持停用")
        scanWeChat()
    }

    func pinWeChatEntry(_ entry: WhitelistEntry) {
        guard let index = entries.firstIndex(where: { $0.id == entry.id }) else { return }
        let prior = entries
        entries[index].automaticSource = nil
        entries[index].sources = ["手动保留（微信发现）"]
        guard saveEntries() else { entries = prior; return }
        syncEntries()
    }

    func scanWeChatNow() {
        nextDiscovery = .distantPast
        scanWeChat()
    }

    private func scanWeChat() {
        guard weChatEnabled, !shuttingDown, !discoveryRunning, !isBusy,
              Date() >= nextDiscovery, storeWritable, weChatSettingsWritable else { return }
        guard isEnabled else { weChatStatus = "开启路由管理后自动检查微信"; return }
        discoveryRunning = true
        Task {
            do {
                let scan = try await Task.detached(priority: .utility) { try WeChatDiscovery.scan() }.value
                guard weChatEnabled, isEnabled, !shuttingDown else { discoveryRunning = false; return }
                let now = Date()
                nextDiscovery = scan.processCount == 0 ? now.addingTimeInterval(12) : .distantPast
                let merged = WeChatAddressPolicy.merge(entries, observed: scan.addresses,
                    excluded: weChatSettings.excludedAddresses, now: now)
                let prior = entries
                let nextEntries = normalized(merged.entries)
                if nextEntries != entries { entries = nextEntries }
                let structuralChange = merged.added > 0 || merged.removed > 0
                if structuralChange || now.timeIntervalSince(lastDiscoverySave) >= 60 {
                    if saveEntries() { lastDiscoverySave = now }
                    else {
                        entries = prior
                        weChatError = "保存动态地址失败，本轮未修改路由。"
                        discoveryRunning = false
                        return
                    }
                }
                if structuralChange {
                    log("微信自动维护：新增 \(merged.added)，清理 \(merged.removed) 个地址")
                    syncEntries()
                }
                weChatError = merged.skipped > 0 ? "地址容量已满，\(merged.skipped) 个新地址未放行。手动条目和当前连接保留。" : nil
                weChatLastScan = DateFormatter.localizedString(from: now, dateStyle: .none, timeStyle: .medium)
                weChatStatus = scan.processCount == 0 ? "微信未运行 · 每 15 秒检查" :
                    "\(scan.processCount) 个进程 · \(scan.addresses.count) 个 IPv6 目标 · \(scan.ipv4Connections) 条 IPv4 · \(scan.proxyConnections) 条本地连接"
            } catch {
                nextDiscovery = Date().addingTimeInterval(12)
                let message = error.localizedDescription
                if weChatError != message { log(message) }
                weChatError = message
                weChatStatus = "检查失败，保留已有地址，15 秒后重试"
            }
            discoveryRunning = false
        }
    }
}
