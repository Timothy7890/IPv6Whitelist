import Foundation
import Darwin

// MARK: - Controller data

struct NetbridgeAddress: Codable, Equatable {
    var ip: String
    var kind: String
    var label: String
    var primary: Bool
}

struct NetbridgeTunnel: Codable {
    var keyID: String
    var clientLabel: String
    var clientAddress: String
    var deviceHostname: String?
    var localAddress: String
    var publicAddress: String
    /// Set by the Controller for nodes reached through an access domain.
    var accessAddress: String?
    var accessStale: Bool?
    var nodeID: String?
    var createdAt: String
    var deviceAddressInfo: [NetbridgeAddress]?

    enum CodingKeys: String, CodingKey {
        case keyID = "key_id"
        case clientLabel = "client_label"
        case clientAddress = "client_address"
        case deviceHostname = "device_hostname"
        case localAddress = "local_address"
        case publicAddress = "public_address"
        case accessAddress = "access_address"
        case accessStale = "access_stale"
        case nodeID = "node_id"
        case createdAt = "created_at"
        case deviceAddressInfo = "device_address_info"
    }
}

struct NetbridgeForward: Equatable, Identifiable {
    var nodeID: String
    var localAddress: String
    /// The address to connect to: the resolved one when the node has it.
    var publicAddress: String
    /// The node's domain failed to resolve, so this is the last known address.
    var stale: Bool = false
    var id: String { "\(nodeID)|\(localAddress)" }

    /// For example: home-1 · 22 → [240e::1]:20100
    var title: String {
        let target = localAddress.hasPrefix("127.0.0.1:") ? String(localAddress.dropFirst("127.0.0.1:".count)) : localAddress
        let node = nodeID.isEmpty ? "" : "\(nodeID) · "
        return "\(node)\(target) → \(publicAddress)\(stale ? "（解析失败）" : "")"
    }
}

/// One authorized key. Identified by key rather than name because the name is
/// the hostname at enrollment and can repeat.
struct NetbridgeDevice: Equatable, Identifiable {
    var keyID: String
    var label: String
    var hostname: String?
    var addresses: [NetbridgeAddress]
    var forwards: [NetbridgeForward]
    var id: String { keyID }
}

private func tunnelDate(_ value: String) -> Date {
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value) ?? .distantPast
}

/// If one key is connected from several places, the newest session wins.
func groupNetbridgeDevices(_ tunnels: [NetbridgeTunnel]) -> [NetbridgeDevice] {
    var devices: [String: NetbridgeDevice] = [:]
    let newestFirst = tunnels.filter { !$0.keyID.isEmpty }.sorted { tunnelDate($0.createdAt) > tunnelDate($1.createdAt) }
    for tunnel in newestFirst {
        var device = devices[tunnel.keyID] ?? NetbridgeDevice(
            keyID: tunnel.keyID,
            label: tunnel.clientLabel.isEmpty ? "未命名设备" : tunnel.clientLabel,
            hostname: tunnel.deviceHostname,
            addresses: tunnel.deviceAddressInfo ?? [],
            forwards: []
        )
        // A session that just connected may not have reported its addresses yet.
        if device.addresses.isEmpty { device.addresses = tunnel.deviceAddressInfo ?? [] }
        let nodeID = tunnel.nodeID ?? ""
        if !device.forwards.contains(where: { $0.localAddress == tunnel.localAddress && $0.nodeID == nodeID }) {
            device.forwards.append(NetbridgeForward(
                nodeID: nodeID,
                localAddress: tunnel.localAddress,
                publicAddress: tunnel.accessAddress.flatMap { $0.isEmpty ? nil : $0 } ?? tunnel.publicAddress,
                stale: tunnel.accessStale ?? false
            ))
        }
        devices[tunnel.keyID] = device
    }
    return devices.values.map { device in
        var device = device
        device.forwards.sort {
            let byTarget = $0.localAddress.localizedStandardCompare($1.localAddress)
            return byTarget == .orderedSame ? $0.nodeID.localizedStandardCompare($1.nodeID) == .orderedAscending : byTarget == .orderedAscending
        }
        return device
    }.sorted { $0.label.localizedStandardCompare($1.label) == .orderedAscending }
}

// MARK: - Mappings

enum SSHAddressPolicy: String, Codable, CaseIterable, Identifiable {
    case lanIPv4
    case publicIPv6
    case tunnelEntry

    var id: String { rawValue }
    var title: String {
        switch self {
        case .lanIPv4: return "局域网 IPv4"
        case .publicIPv6: return "公网 IPv6"
        case .tunnelEntry: return "netbridge 公网入口"
        }
    }
}

struct SSHTarget: Codable, Equatable {
    var hostName: String
    var port: Int?

    var display: String {
        guard let port else { return hostName }
        return hostName.contains(":") ? "[\(hostName)]:\(port)" : "\(hostName):\(port)"
    }
}

struct SSHMapping: Codable, Equatable, Identifiable {
    var id: UUID = UUID()
    var keyID: String
    var deviceLabel: String
    var hostAlias: String
    var policy: SSHAddressPolicy
    /// The B-side target such as 127.0.0.1:22. Used only with tunnelEntry.
    var forwardTarget: String?
    /// The node of that target, since one device can forward it through several.
    var forwardNode: String?
    /// What the generated file currently says, kept while the device is offline.
    var applied: SSHTarget?
    /// nil keeps the main config's value, sshProxyJumpNone connects directly,
    /// anything else is the Host to jump through.
    var proxyJump: String?
    /// Jump-only Hosts added together share this and always share one jump.
    var jumpGroup: UUID?

    /// No device behind it: only proxyJump is written, never an address.
    /// Real devices always have a key, because keyless tunnels are skipped.
    var isJumpOnly: Bool { keyID.isEmpty }
}

let sshJumpOnlyLabel = "无远程配置"

struct SSHJumpGroup: Identifiable, Equatable {
    var id: UUID
    var members: [SSHMapping]
    var proxyJump: String? { members.first?.proxyJump }
    var aliases: [String] { members.map(\.hostAlias) }
    var title: String {
        guard let first = members.first else { return "" }
        return members.count == 1 ? first.hostAlias : "\(first.hostAlias) 等 \(members.count) 个 Host"
    }
}

enum SSHMappingRow: Identifiable, Equatable {
    case single(SSHMapping)
    case group(SSHJumpGroup)

    var id: UUID {
        switch self {
        case .single(let mapping): return mapping.id
        case .group(let group): return group.id
        }
    }
}

/// One row per group, placed where its first member sorts.
func sshMappingRows(_ mappings: [SSHMapping]) -> [SSHMappingRow] {
    var rows: [SSHMappingRow] = []
    var seen = Set<UUID>()
    for mapping in mappings {
        guard mapping.isJumpOnly, let id = mapping.jumpGroup else {
            rows.append(.single(mapping))
            continue
        }
        if seen.insert(id).inserted {
            rows.append(.group(SSHJumpGroup(id: id, members: mappings.filter { $0.jumpGroup == id })))
        }
    }
    return rows
}

/// Mappings saved when ali was the only node.
func assigningDefaultForwardNode(_ mappings: [SSHMapping]) -> [SSHMapping] {
    mappings.map { mapping in
        guard mapping.policy == .tunnelEntry, mapping.forwardTarget != nil, mapping.forwardNode == nil else { return mapping }
        var mapping = mapping
        mapping.forwardNode = "ali"
        return mapping
    }
}

/// Jump-only Hosts saved before groups existed: the same jump becomes one group.
func mergeUngroupedJumpOnly(_ mappings: [SSHMapping]) -> [SSHMapping] {
    var groups: [String: UUID] = [:]
    return mappings.map { mapping in
        guard mapping.isJumpOnly, mapping.jumpGroup == nil else { return mapping }
        var mapping = mapping
        // Control characters cannot appear in a jump, so inherit never collides with one.
        let key = mapping.proxyJump ?? "\u{1}inherit"
        let id = groups[key] ?? UUID()
        groups[key] = id
        mapping.jumpGroup = id
        return mapping
    }
}

/// Replaces a group's members and jump in one step. Throws without changing
/// anything if the new group would not work.
func updatingJumpGroup(_ mappings: [SSHMapping], id: UUID, aliases: [String], jump: String?, hosts: [SSHEffectiveHost]) throws -> [SSHMapping] {
    let others = mappings.filter { $0.jumpGroup != id }
    let members = try makeJumpOnlyMappings(aliases: aliases, jump: jump, hosts: hosts, existing: others, group: id)
    return (others + members).sorted { $0.hostAlias.localizedStandardCompare($1.hostAlias) == .orderedAscending }
}

/// Builds the new mappings for several Hosts sharing one jump. Throws on the
/// first problem, so a batch is either added whole or not at all.
func makeJumpOnlyMappings(aliases: [String], jump: String?, hosts: [SSHEffectiveHost], existing: [SSHMapping], group: UUID = UUID()) throws -> [SSHMapping] {
    guard !aliases.isEmpty else { throw SSHSyncError.message("请至少选择一个 Host。") }
    guard let jump else { throw SSHSyncError.message("请选择跳板或直连。") }
    guard isSafeSSHProxyJump(jump) else { throw SSHSyncError.message("这个跳板名称不能使用。") }
    let existingAliases = Set(existing.map(\.hostAlias))
    var added: [SSHMapping] = []
    let sorted = Set(aliases).sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    for alias in sorted {
        guard isSafeSSHAlias(alias) else { throw SSHSyncError.message("\(alias) 这个 Host 名称不能使用。") }
        guard !existingAliases.contains(alias) else { throw SSHSyncError.message("\(alias) 已经配置过了。") }
        // Checked with the earlier ones included: they can close a loop together.
        if proxyJumpCreatesCycle(alias: alias, jump: jump, hosts: hosts, mappings: existing + added) {
            throw SSHSyncError.message("\(jump) 最终又会跳回 \(alias)，会形成循环，SSH 无法连接。")
        }
        added.append(SSHMapping(keyID: "", deviceLabel: sshJumpOnlyLabel, hostAlias: alias, policy: .lanIPv4, proxyJump: jump, jumpGroup: group))
    }
    return added
}

func isIPLiteral(_ value: String) -> Bool {
    var v4 = in_addr()
    var v6 = in6_addr()
    return value.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
}

/// Values are written into an ssh config, so anything that could start a new
/// option or token is refused.
func isSafeSSHHostName(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 253, !value.hasPrefix("-") else { return false }
    return value.unicodeScalars.allSatisfy {
        ($0.isASCII && CharacterSet.alphanumerics.contains($0)) || $0 == "." || $0 == "-" || $0 == ":"
    }
}

func isSafeSSHAlias(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 255, !value.hasPrefix("-") else { return false }
    let forbidden = CharacterSet.whitespacesAndNewlines
        .union(.controlCharacters)
        .union(CharacterSet(charactersIn: "*?!#\"'\\,%"))
    return value.unicodeScalars.allSatisfy { !forbidden.contains($0) }
}

let sshProxyJumpNone = "none"

func isSafeSSHProxyJump(_ value: String) -> Bool {
    value == sshProxyJumpNone || isSafeSSHAlias(value)
}

/// ProxyJump values can be comma-separated hops written as [user@]host[:port].
private func proxyJumpHops(_ value: String) -> [String] {
    value.split(separator: ",").map { hop in
        var host = String(hop)
        if let at = host.lastIndex(of: "@") { host = String(host[host.index(after: at)...]) }
        if let colon = host.firstIndex(of: ":") { host = String(host[..<colon]) }
        return host
    }
}

/// Whether making `alias` jump through `jump` would lead back to `alias`. Mapped
/// hosts use their chosen jump; the others use what the SSH config says.
func proxyJumpCreatesCycle(alias: String, jump: String, hosts: [SSHEffectiveHost], mappings: [SSHMapping]) -> Bool {
    var visited = Set<String>()
    var pending = proxyJumpHops(jump)
    while let hop = pending.popLast() {
        if hop == alias { return true }
        guard hop != sshProxyJumpNone, visited.insert(hop).inserted else { continue }
        let next = mappings.first { $0.hostAlias == hop }?.proxyJump ?? hosts.first { $0.alias == hop }?.proxyJump
        if let next { pending += proxyJumpHops(next) }
    }
    return false
}

func parseNetbridgeEntry(_ address: String) -> SSHTarget? {
    guard let separator = address.lastIndex(of: ":"),
          let port = Int(address[address.index(after: separator)...]), (1...65535).contains(port) else { return nil }
    var host = String(address[..<separator])
    if host.hasPrefix("["), host.hasSuffix("]") {
        host.removeFirst()
        host.removeLast()
    }
    return isSafeSSHHostName(host) ? SSHTarget(hostName: host, port: port) : nil
}

func resolveSSHTarget(_ mapping: SSHMapping, device: NetbridgeDevice) -> SSHTarget? {
    let kind: String
    switch mapping.policy {
    case .lanIPv4: kind = "lan-ipv4"
    case .publicIPv6: kind = "public-ipv6"
    case .tunnelEntry:
        // Never falls back to another node: a tunnel that is down must not move the Host.
        guard let forward = device.forwards.first(where: {
            $0.localAddress == mapping.forwardTarget && (mapping.forwardNode == nil || $0.nodeID == mapping.forwardNode)
        }) else { return nil }
        return parseNetbridgeEntry(forward.publicAddress)
    }
    guard let address = device.addresses.first(where: { $0.kind == kind && $0.primary }),
          isIPLiteral(address.ip) else { return nil }
    return SSHTarget(hostName: address.ip, port: nil)
}

// MARK: - Whitelist

let sshDynamicAutomaticSource = "ssh-dynamic"
private let whitelistCapacity = 256

struct DynamicWhitelistMerge {
    var entries: [WhitelistEntry]
    var added: [String] = []
    var removed: [String] = []
    /// Removed by hand earlier, which is respected until exclusions are reset.
    var excluded: [String] = []
    var overCapacity: [String] = []
}

/// Current IPv6 address → the Hosts using it. IPv4 addresses and names have no
/// place in the whitelist; jump-only Hosts have no address at all.
func dynamicWhitelistAddresses(_ mappings: [SSHMapping]) -> [String: [String]] {
    var wanted: [String: [String]] = [:]
    for mapping in mappings {
        guard !mapping.isJumpOnly, let host = mapping.applied?.hostName, let address = canonicalIPv6(host) else { continue }
        wanted[address, default: []].append(mapping.hostAlias)
    }
    return wanted.mapValues { $0.sorted { $0.localizedStandardCompare($1) == .orderedAscending } }
}

/// Keeps the entries this feature owns equal to `wanted`. Entries added by hand
/// or imported are never removed or renamed, so an address they already cover
/// needs nothing. A disabled entry stays disabled.
func mergeDynamicWhitelist(_ current: [WhitelistEntry], wanted: [String: [String]],
                           excluded: Set<String>, now: Date) -> DynamicWhitelistMerge {
    var result = DynamicWhitelistMerge(entries: [])
    for var entry in current {
        let isOwned = entry.automaticSource == sshDynamicAutomaticSource
        guard let aliases = wanted[entry.address] else {
            if isOwned { result.removed.append(entry.address) } else { result.entries.append(entry) }
            continue
        }
        // A WeChat entry would expire after a week, so a Host's address takes it over.
        if isOwned || entry.isWeChatAutomatic {
            entry.automaticSource = sshDynamicAutomaticSource
            entry.name = "SSH 动态 · \(aliases.joined(separator: "、"))"
            entry.sources = aliases.map { "SSH 动态更新：\($0)" }
            entry.lastSeen = now
        }
        result.entries.append(entry)
    }
    let present = Set(result.entries.map(\.address))
    for address in wanted.keys.sorted() where !present.contains(address) {
        let aliases = wanted[address] ?? []
        if excluded.contains(address) {
            result.excluded.append(address)
        } else if result.entries.count >= whitelistCapacity {
            result.overCapacity.append(address)
        } else {
            result.entries.append(WhitelistEntry(
                address: address, name: "SSH 动态 · \(aliases.joined(separator: "、"))",
                sources: aliases.map { "SSH 动态更新：\($0)" },
                automaticSource: sshDynamicAutomaticSource, firstSeen: now, lastSeen: now))
            result.added.append(address)
        }
    }
    return result
}

// MARK: - Generated file

/// HostKeyAlias keys known_hosts to the Host instead of its address, so an IP
/// change does not ask to trust the machine again. The key itself is still checked.
func renderDynamicSSHConfig(_ mappings: [SSHMapping]) -> String {
    var lines = ["# 由 IPv6 白名单 App 生成，请勿手动修改；修改会在下次更新时被覆盖。"]
    let sorted = mappings.filter { isSafeSSHAlias($0.hostAlias) }
        .sorted { $0.hostAlias.localizedStandardCompare($1.hostAlias) == .orderedAscending }
    for mapping in sorted {
        var options: [String] = []
        let target = mapping.applied.flatMap { isSafeSSHHostName($0.hostName) ? $0 : nil }
        if let target {
            options.append("    HostName \(target.hostName)")
            if let port = target.port, (1...65535).contains(port) { options.append("    Port \(port)") }
            options.append("    HostKeyAlias netbridge-\(mapping.hostAlias)")
        }
        if let jump = mapping.proxyJump, isSafeSSHProxyJump(jump) { options.append("    ProxyJump \(jump)") }
        if !options.isEmpty { lines += ["", "Host \(mapping.hostAlias)"] + options }
    }
    return lines.joined(separator: "\n") + "\n"
}

// MARK: - Files

enum SSHIncludeStatus: Equatable {
    case active
    case missing
    /// After a Host or Match line, where it would apply to that block only.
    case misplaced
}

enum SSHSyncError: LocalizedError {
    case message(String)
    var errorDescription: String? {
        if case .message(let text) = self { return text }
        return nil
    }
}

struct SSHSyncPaths {
    var config: URL
    var dynamic: URL

    static var standard: SSHSyncPaths {
        let ssh = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh", isDirectory: true)
        return SSHSyncPaths(
            config: ssh.appendingPathComponent("config"),
            dynamic: ssh.appendingPathComponent("config.d/netbridge-dynamic")
        )
    }

    var includeArgument: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path + "/"
        let path = dynamic.path.hasPrefix(home) ? "~/" + dynamic.path.dropFirst(home.count) : dynamic.path
        return path.contains(" ") ? "\"\(path)\"" : path
    }

    var includeLine: String { "Include \(includeArgument)" }
}

func sshIncludeStatus(configText: String, paths: SSHSyncPaths) -> SSHIncludeStatus {
    let wanted = paths.includeArgument.replacingOccurrences(of: "\"", with: "")
    var sawBlock = false
    for raw in configText.components(separatedBy: .newlines) {
        let line = raw.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") { continue }
        let parts = line.split(maxSplits: 1, whereSeparator: { $0.isWhitespace || $0 == "=" }).map(String.init)
        let keyword = parts[0].lowercased()
        if keyword == "host" || keyword == "match" {
            sawBlock = true
        } else if keyword == "include", parts.count > 1 {
            let arguments = parts[1].replacingOccurrences(of: "\"", with: "")
            if arguments == wanted || arguments.split(separator: " ").map(String.init).contains(wanted) {
                return sawBlock ? .misplaced : .active
            }
        }
    }
    return .missing
}

func readSSHIncludeStatus(paths: SSHSyncPaths) -> SSHIncludeStatus {
    guard let data = try? Data(contentsOf: paths.config.resolvingSymlinksInPath()),
          let text = String(data: data, encoding: .utf8) else { return .missing }
    return sshIncludeStatus(configText: text, paths: paths)
}

private func writePrivateFile(_ data: Data, to url: URL, permissions: Int = 0o600) throws {
    try data.write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
}

/// Prepends the Include line, keeping the rest of the file byte for byte, and
/// returns the backup path (nil when there was no file to back up).
@discardableResult
func installSSHInclude(paths: SSHSyncPaths, now: Date = Date()) throws -> URL? {
    let manager = FileManager.default
    // Follow a symlinked config so an atomic write does not replace the link.
    let config = paths.config.resolvingSymlinksInPath()
    var original = Data()
    var permissions = 0o600
    let exists = manager.fileExists(atPath: config.path)
    if exists {
        original = try Data(contentsOf: config)
        guard let text = String(data: original, encoding: .utf8) else {
            throw SSHSyncError.message("SSH 配置不是 UTF-8 文本，为避免损坏没有修改。")
        }
        switch sshIncludeStatus(configText: text, paths: paths) {
        case .active: return nil
        case .misplaced:
            throw SSHSyncError.message("SSH 配置里已有这行 Include，但不在所有 Host 之前。请手动把它移到文件最顶部。")
        case .missing: break
        }
        if let value = try manager.attributesOfItem(atPath: config.path)[.posixPermissions] as? Int {
            permissions = value
        }
    } else {
        try manager.createDirectory(at: config.deletingLastPathComponent(), withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o700])
    }
    var backup: URL?
    if exists {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let url = URL(fileURLWithPath: config.path + ".netbridge-backup-" + formatter.string(from: now))
        try writePrivateFile(original, to: url)
        backup = url
    }
    let header = "# netbridge 动态地址，由 IPv6 白名单 App 添加，必须位于所有 Host 之前。\n\(paths.includeLine)\n\n"
    try writePrivateFile(Data(header.utf8) + original, to: config, permissions: permissions)
    return backup
}

/// Returns true if the file changed.
@discardableResult
func writeDynamicSSHConfig(_ content: String, paths: SSHSyncPaths) throws -> Bool {
    let data = Data(content.utf8)
    if let current = try? Data(contentsOf: paths.dynamic), current == data { return false }
    try FileManager.default.createDirectory(at: paths.dynamic.deletingLastPathComponent(),
                                            withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    try writePrivateFile(data, to: paths.dynamic)
    return true
}

// MARK: - Controller client

private final class RefuseRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? { nil }
}

/// The token must only go where it was configured to go, so redirects and plain
/// HTTP to other machines are refused.
func netbridgeTunnelsURL(controller: String) throws -> URL {
    let trimmed = controller.trimmingCharacters(in: .whitespacesAndNewlines)
    guard var components = URLComponents(string: trimmed), let host = components.host, !host.isEmpty,
          components.scheme == "https" || (components.scheme == "http" && (host == "localhost" || host == "127.0.0.1")) else {
        throw SSHSyncError.message("Controller 地址必须是 https:// 开头的完整地址。")
    }
    components.path = "/v1/tunnels"
    components.query = nil
    guard let url = components.url else { throw SSHSyncError.message("Controller 地址无效。") }
    return url
}

struct SOCKSProxy: Equatable {
    var host: String
    var port: Int
}

/// Accepts host:port or a bare port on this Mac. Empty means connect directly.
func parseSOCKSProxy(_ value: String) throws -> SOCKSProxy? {
    var text = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if text.isEmpty { return nil }
    if text.lowercased().hasPrefix("socks5://") { text.removeFirst("socks5://".count) }
    if Int(text) != nil { text = "127.0.0.1:" + text }
    guard let target = parseNetbridgeEntry(text) else {
        throw SSHSyncError.message("SOCKS5 代理地址格式不对，应为 127.0.0.1:1085。")
    }
    return SOCKSProxy(host: target.hostName, port: target.port ?? 0)
}

struct SOCKSProxyPreset: Identifiable, Equatable {
    var name: String
    var port: Int
    var id: Int { port }
    var address: String { "127.0.0.1:\(port)" }
}

/// Local SOCKS5 forwards on this Mac. Add new ones here.
let socksProxyPresets = [
    SOCKSProxyPreset(name: "3090C-613", port: 1083),
    SOCKSProxyPreset(name: "5070-2048", port: 1092),
    SOCKSProxyPreset(name: "LXZ-606", port: 1081),
    SOCKSProxyPreset(name: "PYX-606", port: 1085),
    SOCKSProxyPreset(name: "macmini-618", port: 1084),
    SOCKSProxyPreset(name: "mybox-abyss", port: 1091),
]

func socksProxyPreset(matching value: String) -> SOCKSProxyPreset? {
    guard let proxy = try? parseSOCKSProxy(value),
          ["127.0.0.1", "localhost"].contains(proxy.host) else { return nil }
    return socksProxyPresets.first { $0.port == proxy.port }
}

func fetchNetbridgeTunnels(controller: String, token: String, socksProxy: String = "") async throws -> [NetbridgeTunnel] {
    var request = URLRequest(url: try netbridgeTunnelsURL(controller: controller), timeoutInterval: 15)
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    let configuration = URLSessionConfiguration.ephemeral
    let proxy = try parseSOCKSProxy(socksProxy)
    if let proxy {
        configuration.connectionProxyDictionary = [
            kCFNetworkProxiesSOCKSEnable as String: 1,
            kCFNetworkProxiesSOCKSProxy as String: proxy.host,
            kCFNetworkProxiesSOCKSPort as String: proxy.port,
        ]
    }
    let session = URLSession(configuration: configuration, delegate: RefuseRedirects(), delegateQueue: nil)
    defer { session.finishTasksAndInvalidate() }
    let data: Data
    let response: URLResponse
    do {
        (data, response) = try await session.data(for: request)
    } catch {
        let route = proxy.map { "（经 SOCKS5 \($0.host):\($0.port)）" } ?? ""
        throw SSHSyncError.message("无法连接 Controller\(route)：\(error.localizedDescription)")
    }
    guard let http = response as? HTTPURLResponse else { throw SSHSyncError.message("Controller 返回了无效响应。") }
    switch http.statusCode {
    case 200: break
    case 401, 403: throw SSHSyncError.message("令牌无效或没有权限，请重新设置只读令牌。")
    default: throw SSHSyncError.message("Controller 返回错误 \(http.statusCode)。")
    }
    do {
        return try JSONDecoder().decode([NetbridgeTunnel].self, from: data)
    } catch {
        throw SSHSyncError.message("无法解析 Controller 的返回内容。")
    }
}

// MARK: - Filtering

/// Every space-separated word must match the alias or the address, in any order.
func filterSSHHosts(_ hosts: [SSHEffectiveHost], query: String) -> [SSHEffectiveHost] {
    let words = query.split(whereSeparator: \.isWhitespace).map(String.init)
    guard !words.isEmpty else { return hosts }
    return hosts.filter { host in
        words.allSatisfy { host.alias.localizedCaseInsensitiveContains($0) || host.display.localizedCaseInsensitiveContains($0) }
    }
}

func filterSSHMappings(_ mappings: [SSHMapping], query: String) -> [SSHMapping] {
    let words = query.split(whereSeparator: \.isWhitespace).map(String.init)
    guard !words.isEmpty else { return mappings }
    return mappings.filter { mapping in
        let fields = [mapping.hostAlias, mapping.deviceLabel, mapping.isJumpOnly ? "" : mapping.policy.title, mapping.applied?.display ?? ""]
        return words.allSatisfy { word in fields.contains { $0.localizedCaseInsensitiveContains(word) } }
    }
}

/// Moves a list highlight. Going up from the first item clears it, which hands
/// the keyboard back to the search field; the last item stops at the end.
func movedHighlight(current: String?, items: [String], delta: Int) -> String? {
    guard !items.isEmpty else { return nil }
    guard let current, let index = items.firstIndex(of: current) else {
        return delta > 0 ? items[0] : nil
    }
    let next = index + delta
    if next < 0 { return nil }
    return items[min(next, items.count - 1)]
}
