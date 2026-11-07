import AppKit
import Foundation
import Security

protocol SSHSyncTokenStore {
    func read() -> String?
    func save(_ token: String) throws
    func delete()
}

struct KeychainTokenStore: SSHSyncTokenStore {
    private let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "local.timo.IPv6Whitelist.netbridge",
        kSecAttrAccount as String: "read-only-token",
    ]

    func read() -> String? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func save(_ token: String) throws {
        let data = Data(token.utf8)
        var status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw SSHSyncError.message("无法保存令牌到钥匙串（错误 \(status)）。")
        }
    }

    func delete() {
        SecItemDelete(query as CFDictionary)
    }
}

struct SSHSyncSettings: Codable, Equatable {
    var controllerURL = "https://nbg.xingxingdiandian.xyz"
    var socksProxy: String?
    var mappings: [SSHMapping] = []
}

enum SSHMappingState: Equatable {
    case upToDate
    case pending(SSHTarget)
    case offline
    case noAddress
    case jumpOnly
}

@MainActor
final class SSHSyncModel: ObservableObject {
    static let shared = SSHSyncModel(log: { AppModel.shared.log($0) },
                                     syncWhitelist: { AppModel.shared.syncSSHDynamicAddresses($0) })

    @Published private(set) var settings = SSHSyncSettings()
    @Published private(set) var devices: [NetbridgeDevice] = []
    @Published private(set) var hosts: [SSHEffectiveHost] = []
    @Published private(set) var includeStatus = SSHIncludeStatus.missing
    @Published private(set) var hasToken = false
    @Published private(set) var isBusy = false
    @Published private(set) var lastFetched: Date?
    @Published var errorText: String?
    @Published var noticeText: String?

    let paths: SSHSyncPaths
    private let tokenStore: SSHSyncTokenStore
    private let settingsURL: URL
    private let log: (String) -> Void
    private let syncWhitelist: ([String: [String]]) -> String?
    private var settingsWritable = true

    init(paths: SSHSyncPaths = .standard,
         tokenStore: SSHSyncTokenStore = KeychainTokenStore(),
         settingsURL: URL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/IPv6Whitelist/ssh-config-sync.json"),
         log: @escaping (String) -> Void,
         syncWhitelist: @escaping ([String: [String]]) -> String? = { _ in nil }) {
        self.paths = paths
        self.tokenStore = tokenStore
        self.settingsURL = settingsURL
        self.log = log
        self.syncWhitelist = syncWhitelist
        loadSettings()
        reloadLocalState()
        hasToken = tokenStore.read() != nil
    }

    var pendingCount: Int {
        settings.mappings.filter {
            if case .pending = state(of: $0) { return true }
            return false
        }.count
    }

    var mappedAliases: Set<String> { Set(settings.mappings.map(\.hostAlias)) }

    func device(for mapping: SSHMapping) -> NetbridgeDevice? {
        devices.first { $0.keyID == mapping.keyID }
    }

    func effectiveHost(for alias: String) -> SSHEffectiveHost? {
        hosts.first { $0.alias == alias }
    }

    func state(of mapping: SSHMapping) -> SSHMappingState {
        if mapping.isJumpOnly { return .jumpOnly }
        guard let device = device(for: mapping) else { return .offline }
        guard let target = resolveSSHTarget(mapping, device: device) else { return .noAddress }
        return target == mapping.applied ? .upToDate : .pending(target)
    }

    func reloadLocalState() {
        includeStatus = readSSHIncludeStatus(paths: paths)
        hosts = SSHImporter.effectiveHosts(configPath: paths.config.path)
    }

    func setConnection(controller: String, socksProxy: String) {
        settings.controllerURL = controller.trimmingCharacters(in: .whitespacesAndNewlines)
        let proxy = socksProxy.trimmingCharacters(in: .whitespacesAndNewlines)
        settings.socksProxy = proxy.isEmpty ? nil : proxy
        saveSettings()
    }

    /// Returns an error to show in the sheet, or nil on success.
    func setToken(_ value: String) -> String? {
        let token = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard token.count >= 16, token.unicodeScalars.allSatisfy({ $0.isASCII && !CharacterSet.whitespacesAndNewlines.contains($0) }) else {
            return "令牌格式不对：至少 16 个字符，不能包含空格。"
        }
        do {
            try tokenStore.save(token)
            hasToken = true
            log("netbridge 只读令牌已保存到钥匙串")
            Task { await refresh() }
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    func deleteToken() {
        tokenStore.delete()
        hasToken = false
        devices = []
        log("已从钥匙串删除 netbridge 只读令牌")
    }

    func enableInclude() {
        do {
            let backup = try installSSHInclude(paths: paths)
            reloadLocalState()
            if let backup {
                noticeText = "已启用，原配置备份为 \(backup.lastPathComponent)。"
                log("SSH 配置已添加 Include，备份：\(backup.path)")
            }
            errorText = nil
        } catch {
            reloadLocalState()
            errorText = error.localizedDescription
        }
    }

    func refresh() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        _ = await fetchDevices()
    }

    private func fetchDevices() async -> Bool {
        reloadLocalState()
        guard let token = tokenStore.read() else {
            hasToken = false
            errorText = "还没有设置只读令牌。"
            return false
        }
        hasToken = true
        do {
            devices = groupNetbridgeDevices(try await fetchNetbridgeTunnels(
                controller: settings.controllerURL, token: token, socksProxy: settings.socksProxy ?? "")
            )
            lastFetched = Date()
            errorText = nil
            return true
        } catch {
            errorText = error.localizedDescription
            log("读取 netbridge 设备失败：\(error.localizedDescription)")
            return false
        }
    }

    func proxyJumpError(alias: String, jump: String?) -> String? {
        guard let jump else { return nil }
        guard isSafeSSHProxyJump(jump) else { return "这个跳板名称不能使用。" }
        if proxyJumpCreatesCycle(alias: alias, jump: jump, hosts: hosts, mappings: settings.mappings) {
            return "\(jump) 最终又会跳回 \(alias)，会形成循环，SSH 无法连接。"
        }
        return nil
    }

    /// Takes effect right away: unlike addresses, it needs nothing from the Controller.
    func setProxyJump(_ jump: String?, for mapping: SSHMapping) {
        if let problem = proxyJumpError(alias: mapping.hostAlias, jump: jump) {
            errorText = problem
            return
        }
        var updated = settings.mappings
        guard let index = updated.firstIndex(where: { $0.id == mapping.id }) else { return }
        updated[index].proxyJump = jump
        do {
            try writeDynamicSSHConfig(renderDynamicSSHConfig(updated), paths: paths)
        } catch {
            errorText = "写入 SSH 配置失败：\(error.localizedDescription)"
            return
        }
        settings.mappings = updated
        saveSettings()
        reloadLocalState()
        errorText = nil
        log("\(mapping.hostAlias) 的跳板改为：\(jump == nil ? "沿用主配置" : jump == sshProxyJumpNone ? "直连" : jump!)")
    }

    func addMapping(device: NetbridgeDevice, alias: String, policy: SSHAddressPolicy, forwardTarget: String?, proxyJump: String? = nil) -> String? {
        guard isSafeSSHAlias(alias) else { return "这个 Host 名称不能用于自动更新。" }
        guard !mappedAliases.contains(alias) else { return "这个 Host 已经配置过了。" }
        if policy == .tunnelEntry, forwardTarget == nil { return "请选择要使用的转发目标。" }
        if let problem = proxyJumpError(alias: alias, jump: proxyJump) { return problem }
        var updated = settings.mappings
        updated.append(SSHMapping(
            keyID: device.keyID, deviceLabel: device.label, hostAlias: alias, policy: policy,
            forwardTarget: policy == .tunnelEntry ? forwardTarget : nil, proxyJump: proxyJump
        ))
        updated.sort { $0.hostAlias.localizedStandardCompare($1.hostAlias) == .orderedAscending }
        if proxyJump != nil {
            do {
                try writeDynamicSSHConfig(renderDynamicSSHConfig(updated), paths: paths)
            } catch {
                return "写入 SSH 配置失败：\(error.localizedDescription)"
            }
        }
        settings.mappings = updated
        saveSettings()
        reloadLocalState()
        log("新增 SSH 动态更新：\(device.label) → \(alias)（\(policy.title)）")
        return nil
    }

    /// Takes effect right away, so it needs the Include to be active. Returns an
    /// error to show in the sheet, or nil on success; nothing is written on error.
    func addJumpOnlyMappings(aliases: [String], proxyJump: String?) -> String? {
        guard includeStatus == .active else { return "请先启用 SSH 配置中的 Include。" }
        var updated = settings.mappings
        do {
            updated += try makeJumpOnlyMappings(aliases: aliases, jump: proxyJump, hosts: hosts, existing: updated)
            updated.sort { $0.hostAlias.localizedStandardCompare($1.hostAlias) == .orderedAscending }
            try writeDynamicSSHConfig(renderDynamicSSHConfig(updated), paths: paths)
        } catch let error as SSHSyncError {
            return error.localizedDescription
        } catch {
            return "写入 SSH 配置失败：\(error.localizedDescription)"
        }
        settings.mappings = updated
        saveSettings()
        reloadLocalState()
        let jumpText = proxyJump == sshProxyJumpNone ? "直连" : proxyJump ?? ""
        log("新增无远程配置（跳板：\(jumpText)）：\(aliases.sorted().joined(separator: "、"))")
        return nil
    }

    /// Changes a group's members and jump together. Returns an error to show, or
    /// nil on success; nothing is written on error.
    func saveJumpGroup(id: UUID, aliases: [String], proxyJump: String?) -> String? {
        guard includeStatus == .active else { return "请先启用 SSH 配置中的 Include。" }
        let updated: [SSHMapping]
        do {
            updated = try updatingJumpGroup(settings.mappings, id: id, aliases: aliases, jump: proxyJump, hosts: hosts)
            try writeDynamicSSHConfig(renderDynamicSSHConfig(updated), paths: paths)
        } catch let error as SSHSyncError {
            return error.localizedDescription
        } catch {
            return "写入 SSH 配置失败：\(error.localizedDescription)"
        }
        settings.mappings = updated
        saveSettings()
        reloadLocalState()
        errorText = nil
        let jumpText = proxyJump == sshProxyJumpNone ? "直连" : proxyJump ?? ""
        log("组合已更新（跳板：\(jumpText)）：\(aliases.sorted().joined(separator: "、"))")
        return nil
    }

    func removeJumpGroup(_ group: SSHJumpGroup) {
        let remaining = settings.mappings.filter { $0.jumpGroup != group.id }
        do {
            try writeDynamicSSHConfig(renderDynamicSSHConfig(remaining), paths: paths)
            settings.mappings = remaining
            saveSettings()
            reloadLocalState()
            log("移除组合：\(group.aliases.joined(separator: "、"))")
        } catch {
            errorText = "写入 SSH 配置失败：\(error.localizedDescription)"
        }
    }

    func setPolicy(_ policy: SSHAddressPolicy, for mapping: SSHMapping) {
        guard let index = settings.mappings.firstIndex(where: { $0.id == mapping.id }) else { return }
        settings.mappings[index].policy = policy
        if policy == .tunnelEntry, settings.mappings[index].forwardTarget == nil {
            let forwards = device(for: mapping)?.forwards ?? []
            settings.mappings[index].forwardTarget = (forwards.first { $0.localAddress.hasSuffix(":22") } ?? forwards.first)?.localAddress
        }
        saveSettings()
    }

    /// Removing also drops the Host from the generated file right away, so the
    /// main config's own HostName takes effect again.
    func removeMapping(_ mapping: SSHMapping) {
        let remaining = settings.mappings.filter { $0.id != mapping.id }
        do {
            try writeDynamicSSHConfig(renderDynamicSSHConfig(remaining), paths: paths)
            settings.mappings = remaining
            saveSettings()
            reloadLocalState()
            log("移除 SSH 动态更新：\(mapping.hostAlias)")
            noticeText = syncWhitelist(dynamicWhitelistAddresses(remaining)).map { "已移除 \(mapping.hostAlias)，\($0)。" }
        } catch {
            errorText = "写入 SSH 配置失败：\(error.localizedDescription)"
        }
    }

    func updateAll() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        noticeText = nil
        guard await fetchDevices() else { return }
        guard includeStatus == .active else {
            errorText = "请先启用 SSH 配置中的 Include。"
            return
        }
        var updated = settings.mappings
        var changes: [String] = []
        var skipped = 0
        for index in updated.indices {
            switch state(of: updated[index]) {
            case .pending(let target):
                let old = updated[index].applied?.display ?? "主配置中的值"
                changes.append("\(updated[index].hostAlias)：\(old) → \(target.display)")
                updated[index].applied = target
            case .offline, .noAddress:
                skipped += 1
            case .upToDate, .jumpOnly:
                break
            }
        }
        do {
            // The file comes first: a failed write must not record values it does not contain.
            try writeDynamicSSHConfig(renderDynamicSSHConfig(updated), paths: paths)
        } catch {
            errorText = "写入 SSH 配置失败：\(error.localizedDescription)"
            return
        }
        settings.mappings = updated
        saveSettings()
        reloadLocalState()
        changes.forEach { log("SSH 配置已更新 \($0)") }
        let skippedText = skipped > 0 ? "，\(skipped) 个因设备离线或没有对应地址而保留原值" : ""
        // Offline devices keep their last address, and so does the whitelist.
        let whitelistText = syncWhitelist(dynamicWhitelistAddresses(updated)).map { "；\($0)" } ?? ""
        noticeText = (changes.isEmpty ? "没有需要更新的地址\(skippedText)" : "已更新 \(changes.count) 个 Host\(skippedText)") + whitelistText + "。"
    }

    func revealGeneratedFile() {
        NSWorkspace.shared.activateFileViewerSelecting([paths.dynamic])
    }

    private func loadSettings() {
        guard FileManager.default.fileExists(atPath: settingsURL.path) else { return }
        do {
            settings = try JSONDecoder().decode(SSHSyncSettings.self, from: Data(contentsOf: settingsURL))
            let merged = mergeUngroupedJumpOnly(settings.mappings)
            if merged != settings.mappings {
                settings.mappings = merged
                saveSettings()
            }
        } catch {
            settingsWritable = false
            errorText = "ssh-config-sync.json 无法读取，已保留原文件，当前不会保存修改。"
        }
    }

    private func saveSettings() {
        guard settingsWritable else { return }
        do {
            try FileManager.default.createDirectory(at: settingsURL.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(settings).write(to: settingsURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: settingsURL.path)
        } catch {
            errorText = "保存设置失败：\(error.localizedDescription)"
        }
    }
}

#if DEBUG_SSH_SYNC_PREVIEW
extension SSHSyncModel {
    func loadPreview(devices: [NetbridgeDevice], settings: SSHSyncSettings, include: SSHIncludeStatus) {
        self.devices = devices
        self.settings = settings
        includeStatus = include
        hasToken = true
        lastFetched = Date()
    }
}
#endif
