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
    var createdAt: String
    var deviceAddressInfo: [NetbridgeAddress]?

    enum CodingKeys: String, CodingKey {
        case keyID = "key_id"
        case clientLabel = "client_label"
        case clientAddress = "client_address"
        case deviceHostname = "device_hostname"
        case localAddress = "local_address"
        case publicAddress = "public_address"
        case createdAt = "created_at"
        case deviceAddressInfo = "device_address_info"
    }
}

struct NetbridgeForward: Equatable, Identifiable {
    var localAddress: String
    var publicAddress: String
    var id: String { localAddress }
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
        if !device.forwards.contains(where: { $0.localAddress == tunnel.localAddress }) {
            device.forwards.append(NetbridgeForward(localAddress: tunnel.localAddress, publicAddress: tunnel.publicAddress))
        }
        devices[tunnel.keyID] = device
    }
    return devices.values.map { device in
        var device = device
        device.forwards.sort { $0.localAddress.localizedStandardCompare($1.localAddress) == .orderedAscending }
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
    /// What the generated file currently says, kept while the device is offline.
    var applied: SSHTarget?
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
        guard let forward = device.forwards.first(where: { $0.localAddress == mapping.forwardTarget }) else { return nil }
        return parseNetbridgeEntry(forward.publicAddress)
    }
    guard let address = device.addresses.first(where: { $0.kind == kind && $0.primary }),
          isIPLiteral(address.ip) else { return nil }
    return SSHTarget(hostName: address.ip, port: nil)
}

// MARK: - Generated file

/// HostKeyAlias keys known_hosts to the Host instead of its address, so an IP
/// change does not ask to trust the machine again. The key itself is still checked.
func renderDynamicSSHConfig(_ mappings: [SSHMapping]) -> String {
    var lines = ["# 由 IPv6 白名单 App 生成，请勿手动修改；修改会在下次更新时被覆盖。"]
    let applied = mappings.filter { isSafeSSHAlias($0.hostAlias) && $0.applied != nil }
        .sorted { $0.hostAlias.localizedStandardCompare($1.hostAlias) == .orderedAscending }
    for mapping in applied {
        guard let target = mapping.applied, isSafeSSHHostName(target.hostName) else { continue }
        lines += ["", "Host \(mapping.hostAlias)", "    HostName \(target.hostName)"]
        if let port = target.port, (1...65535).contains(port) { lines.append("    Port \(port)") }
        lines.append("    HostKeyAlias netbridge-\(mapping.hostAlias)")
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

func fetchNetbridgeTunnels(controller: String, token: String) async throws -> [NetbridgeTunnel] {
    var request = URLRequest(url: try netbridgeTunnelsURL(controller: controller), timeoutInterval: 15)
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    let session = URLSession(configuration: .ephemeral, delegate: RefuseRedirects(), delegateQueue: nil)
    defer { session.finishTasksAndInvalidate() }
    let data: Data
    let response: URLResponse
    do {
        (data, response) = try await session.data(for: request)
    } catch {
        throw SSHSyncError.message("无法连接 Controller：\(error.localizedDescription)")
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
