import Foundation
import Darwin

// This executable is a short-lived, explicitly authorized route controller. It
// never accepts shell commands, file paths, network interfaces, or CIDR ranges.
private let maximumRequestBytes = 65_536
private let maximumAddresses = 256
private let subprocessTimeout: TimeInterval = 3
private let clientDeadline: TimeInterval = 3
private let heartbeatTimeout: TimeInterval = 90
private var helperExitRequested: sig_atomic_t = 0

private struct CommandResult {
    var status: Int32
    var output: String
    var timedOut: Bool
}

private func monotonicNow() -> TimeInterval { ProcessInfo.processInfo.systemUptime }

// Read output while the child runs so neither a full pipe nor a stuck command
// can indefinitely block cleanup or the heartbeat watchdog.
private func run(_ executable: String, _ arguments: [String]) -> CommandResult {
    let result = BoundedCommandRunner.run(executable, arguments, timeout: subprocessTimeout, outputLimit: 2_097_152)
    return CommandResult(status: result.code, output: result.output, timedOut: result.code == -2)
}

private func ipv6Bytes(_ value: String) -> [UInt8]? {
    var address = in6_addr()
    guard value.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return nil }
    return withUnsafeBytes(of: &address) { Array($0) }
}

private func rawCanonicalIPv6(_ value: String) -> String? {
    guard !value.contains("%"), !value.contains("/"), !value.isEmpty, value.count < 46 else { return nil }
    var address = in6_addr()
    guard value.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return nil }
    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil else { return nil }
    return String(cString: buffer)
}

// Scoped link-local router addresses must retain their zone. A zone identifies
// the gateway; it does not make the host route itself IFSCOPE.
private func canonicalGateway(_ input: String) -> String? {
    let pieces = input.split(separator: "%", omittingEmptySubsequences: false)
    guard pieces.count == 1 || (pieces.count == 2 && pieces[1] == "en0"),
          let address = rawCanonicalIPv6(String(pieces[0])), let bytes = ipv6Bytes(address) else { return nil }
    let linkLocal = bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
    let unicast = (bytes[0] & 0xe0) == 0x20 || (bytes[0] & 0xfe) == 0xfc
    guard linkLocal || unicast else { return nil }
    return linkLocal ? address + "%en0" : address
}

private func routeAddress(_ destination: String) -> String? {
    let value = destination.hasSuffix("/128") ? String(destination.dropLast(4)) : destination
    return canonicalIPv6(value)
}

private func parseRoutes(_ text: String) -> [RouteRecord] {
    text.split(whereSeparator: \.isNewline).compactMap { line in
        let parts = line.split(whereSeparator: \.isWhitespace).map(String.init)
        guard parts.count >= 4, parts[2].contains("U"),
              parts[0] == "default" || parts[0].contains(":") else { return nil }
        return RouteRecord(destination: parts[0], gateway: parts[1], flags: parts[2], interface: parts[3])
    }
}

// A router commonly reuses fe80::1 on entirely different networks. Track the
// usable local addresses as well as the router, so a network/prefix change
// recreates routes that may retain an old interface-address association.
private func usableWiFiIPv6Fingerprint(_ text: String) -> String? {
    guard text.split(whereSeparator: \.isNewline).contains(where: { $0.trimmingCharacters(in: .whitespaces) == "status: active" }),
          text.first(where: { $0 == "\n" }) != nil,
          text.components(separatedBy: "\n").first?.contains("<UP,") == true else { return nil }
    let addresses: [String] = text.split(whereSeparator: \.isNewline).compactMap { line in
        let fields = line.split(whereSeparator: \.isWhitespace)
        guard fields.count > 1, fields[0] == "inet6",
              !fields.contains("tentative"), !fields.contains("duplicated"),
              !fields.contains("deprecated"), !fields.contains("detached"),
              let address = rawCanonicalIPv6(String(fields[1])), let bytes = ipv6Bytes(address),
              (bytes[0] & 0xe0) == 0x20 || (bytes[0] & 0xfe) == 0xfc else { return nil }
        return address
    }
    guard !addresses.isEmpty else { return nil }
    return Set(addresses).sorted().joined(separator: ",")
}

private func hasUsableWiFiIPv6(_ text: String) -> Bool {
    usableWiFiIPv6Fingerprint(text) != nil
}

private func routeNetworkChanged(oldGateway: String, oldFingerprint: String?,
                                 gateway: String?, fingerprint: String?) -> Bool {
    gateway != oldGateway || fingerprint == nil || fingerprint != oldFingerprint
}

private func currentWiFiGateway(routes: [RouteRecord], ifconfig: String, scopedRoute: String) -> String? {
    guard hasUsableWiFiIPv6(ifconfig) else { return nil }
    let candidates = routes.filter {
        $0.destination == "default" && $0.interface == "en0" && $0.flags.contains("I") &&
        $0.flags.contains("G") && !$0.flags.contains("R") && !$0.flags.contains("B")
    }.compactMap { canonicalGateway($0.gateway) }
    guard !candidates.isEmpty else { return nil }
    let lines = scopedRoute.components(separatedBy: "\n")
    func value(_ key: String) -> String? {
        lines.first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix(key + ":") })?
            .components(separatedBy: ":").dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespaces)
    }
    guard value("interface") == "en0", value("flags")?.contains("IFSCOPE") == true,
          let router = value("gateway").flatMap(canonicalGateway), candidates.contains(router) else { return nil }
    return router
}

private func isOwnedMatch(_ route: RouteRecord, address: String, gateway: String) -> Bool {
    routeAddress(route.destination) == address && route.interface == "en0" &&
    canonicalGateway(route.gateway) == gateway && route.flags.contains("S") &&
    route.flags.contains("H") && route.flags.contains("G") && !route.flags.contains("I") &&
    !route.flags.contains("R") && !route.flags.contains("B")
}

// A scoped Wi-Fi link-local gateway attached to a utun interface is an
// unusable leftover after a network switch. Recovery is restricted to desired
// single-host rules and only when that old gateway is absent from en0 defaults.
private func isStrandedWiFiRoute(_ route: RouteRecord, address: String,
                                currentGateway: String, routes: [RouteRecord]) -> Bool {
    guard routeAddress(route.destination) == address, route.interface.hasPrefix("utun"),
          route.gateway.hasSuffix("%en0"), let old = canonicalGateway(route.gateway),
          old != currentGateway, let raw = old.split(separator: "%").first,
          let bytes = ipv6Bytes(String(raw)), bytes[0] == 0xfe, bytes[1] & 0xc0 == 0x80,
          route.flags.contains("S"), route.flags.contains("H"), route.flags.contains("G"),
          !route.flags.contains("I"), !route.flags.contains("R"), !route.flags.contains("B") else { return false }
    return !routes.contains { $0.destination == "default" && $0.interface == "en0" && canonicalGateway($0.gateway) == old }
}

private func exactUnscopedRoutes(_ routes: [RouteRecord], address: String) -> [RouteRecord] {
    routes.filter { routeAddress($0.destination) == address && !$0.flags.contains("I") }
}

private func broadDefaults(_ routes: [RouteRecord]) -> [RouteRecord] {
    routes.filter { $0.destination == "default" && $0.interface == "en0" && !$0.flags.contains("I") }
}

private final class RouteController {
    var enabled = false
    private var desired: Set<String> = []
    private var owned: [String: String] = [:]
    // Keep the fingerprint with each owned route. If deletion fails, retaining
    // its old fingerprint makes the next poll retry instead of accepting it.
    private var ownedFingerprints: [String: String] = [:]
    private var duplicates: [String] = []
    private(set) var status = HelperStatus()

    private func snapshot() throws -> [RouteRecord] {
        let result = run("/usr/sbin/netstat", ["-rn", "-f", "inet6"])
        guard result.status == 0 && !result.timedOut else { throw helperError("无法读取 IPv6 路由表") }
        return parseRoutes(result.output)
    }

    func setAddresses(_ values: [String]) throws {
        guard values.count <= maximumAddresses else { throw helperError("白名单最多支持 256 个地址") }
        var unique = Set<String>()
        var repeats = Set<String>()
        for value in values {
            guard let address = canonicalIPv6(value), !value.contains("%"), !value.contains("/") else {
                throw helperError("无效 IPv6 主机地址：\(value.prefix(100))")
            }
            if !unique.insert(address).inserted { repeats.insert(address) }
        }
        desired = unique
        duplicates = repeats.sorted().map { "重复地址已合并：\($0)" }
    }

    // Route ownership is retained only while the exact static, unscoped host
    // route we installed is still present. Existing routes are never adopted.
    private func deleteOwned(_ address: String, gateway: String) throws {
        let fresh = try snapshot()
        let exact = exactUnscopedRoutes(fresh, address: address)
        guard exact.count == 1, isOwnedMatch(exact[0], address: address, gateway: gateway) else {
            owned.removeValue(forKey: address)
            ownedFingerprints.removeValue(forKey: address)
            if !exact.isEmpty { throw helperError("路由已被其他程序修改，已停止管理：\(address)") }
            return
        }
        let result = run("/sbin/route", ["-n", "delete", "-inet6", "-host", address, gateway])
        let remaining = try snapshot()
        if !remaining.contains(where: { isOwnedMatch($0, address: address, gateway: gateway) }) {
            owned.removeValue(forKey: address)
            ownedFingerprints.removeValue(forKey: address)
        } else {
            throw helperError(result.timedOut ? "删除路由超时：\(address)" : "无法删除本应用路由：\(address)")
        }
    }

    func reconcile() {
        var errors: [String] = []
        var conflicts = duplicates
        do {
            var routes = try snapshot()
            let interfaceState = run("/sbin/ifconfig", ["en0"])
            let scoped = run("/sbin/route", ["-n", "get", "-inet6", "-ifscope", "en0", "default"])
            let gateway = (interfaceState.status == 0 && !interfaceState.timedOut && scoped.status == 0 && !scoped.timedOut)
                ? currentWiFiGateway(routes: routes, ifconfig: interfaceState.output, scopedRoute: scoped.output) : nil
            // No gateway/disconnected means no current fingerprint. Successful
            // stale-route removal below also forgets that route's fingerprint.
            let fingerprint = gateway == nil ? nil : usableWiFiIPv6Fingerprint(interfaceState.output)

            // Always retire stale owned routes, including after Wi-Fi loses IPv6.
            for (address, oldGateway) in owned.sorted(by: { $0.key < $1.key }) {
                let exact = exactUnscopedRoutes(routes, address: address)
                if exact.count != 1 || !isOwnedMatch(exact[0], address: address, gateway: oldGateway) {
                    owned.removeValue(forKey: address)
                    ownedFingerprints.removeValue(forKey: address)
                    if !exact.isEmpty { conflicts.append("已有路由由其他程序管理：\(address)") }
                    continue
                }
                if !enabled || !desired.contains(address) ||
                    routeNetworkChanged(oldGateway: oldGateway, oldFingerprint: ownedFingerprints[address],
                                        gateway: gateway, fingerprint: fingerprint) {
                    do { try deleteOwned(address, gateway: oldGateway) }
                    catch { errors.append(error.localizedDescription) }
                }
            }
            routes = try snapshot()

            if enabled, let gateway, let fingerprint {
                var mutations = 0
                for address in desired.sorted() where owned[address] == nil {
                    var exact = exactUnscopedRoutes(routes, address: address)
                    if !exact.isEmpty {
                        if exact.count == 1 && isStrandedWiFiRoute(exact[0], address: address, currentGateway: gateway, routes: routes) {
                            if mutations >= 16 { continue }
                            // Recheck before deleting, never delete an ambiguous or changed rule.
                            routes = try snapshot()
                            exact = exactUnscopedRoutes(routes, address: address)
                            if exact.count == 1 && isStrandedWiFiRoute(exact[0], address: address, currentGateway: gateway, routes: routes) {
                                let removed = run("/sbin/route", ["-n", "delete", "-inet6", "-host", address, exact[0].gateway])
                                mutations += 1
                                routes = try snapshot()
                                if removed.status != 0 || !exactUnscopedRoutes(routes, address: address).isEmpty {
                                    errors.append("失效 Wi-Fi 路由清理失败：\(address)")
                                    continue
                                }
                            } else {
                                conflicts.append("路由在恢复前已变化，保留：\(address)")
                                continue
                            }
                        } else {
                            // Existing conflicts need no per-address subprocess.
                            conflicts.append("保留已有主机路由，未覆盖：\(address)")
                            continue
                        }
                    }
                    if mutations >= 16 { continue }
                    routes = try snapshot()
                    if !exactUnscopedRoutes(routes, address: address).isEmpty {
                        conflicts.append("保留已有主机路由，未覆盖：\(address)")
                        continue
                    }
                    mutations += 1
                    let result = run("/sbin/route", ["-n", "add", "-inet6", "-host", address, gateway, "-static"])
                    guard result.status == 0 && !result.timedOut else {
                        errors.append("添加路由失败：\(address)")
                        continue
                    }
                    owned[address] = gateway
                    ownedFingerprints[address] = fingerprint
                    routes = try snapshot()
                    if !routes.contains(where: { isOwnedMatch($0, address: address, gateway: gateway) }) {
                        owned.removeValue(forKey: address)
                        ownedFingerprints.removeValue(forKey: address)
                        errors.append("未能确认路由生效：\(address)")
                    }
                }
            }
            routes = try snapshot()
            // Never mistake one of our /128 exceptions for the ordinary public
            // route. No packets are sent by this route-table query.
            let candidates = ["2606:4700:4700::1111", "2001:4860:4860::8888"] +
                (1...257).map { "2606:4700:4700::100:" + String($0, radix: 16) }
            let probe = candidates.first { !desired.contains($0) && owned[$0] == nil }!
            let publicRoute = run("/sbin/route", ["-n", "get", "-inet6", probe])
            let primary = publicRoute.status == 0 && !publicRoute.timedOut
                ? publicRoute.output.split(whereSeparator: \.isNewline)
                    .first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("interface:") })?
                    .split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces) : nil
            status = HelperStatus(enabled: enabled, wifiGateway: gateway,
                activeRoutes: owned.sorted(by: { $0.key < $1.key }).map { ManagedRoute(address: $0.key, gateway: $0.value) },
                conflicts: Array(Set(conflicts)).sorted(), error: errors.isEmpty ? nil : errors.joined(separator: "\n"),
                broadDefaults: broadDefaults(routes), defaultIPv6Interface: primary,
                updatedAt: Date().timeIntervalSince1970)
        } catch {
            status.enabled = enabled
            status.error = error.localizedDescription
            status.updatedAt = Date().timeIntervalSince1970
        }
    }

    func cleanup() {
        enabled = false
        // On ordinary failures retry once, never use a broad deletion fallback.
        for _ in 0..<2 {
            for (address, gateway) in owned.sorted(by: { $0.key < $1.key }) {
                try? deleteOwned(address, gateway: gateway)
            }
            if owned.isEmpty { break }
        }
    }

    func removeBroadDefault(gateway requested: String) throws {
        guard let gateway = canonicalGateway(requested) else { throw helperError("无效 Wi-Fi 网关") }
        let routes = try snapshot()
        // Refuse ambiguous multipath tables altogether: route(8)'s deletion
        // lookup must have exactly one non-scoped default it could select.
        let candidates = routes.filter { $0.destination == "default" && !$0.flags.contains("I") }
        guard candidates.count == 1, let candidate = candidates.first,
              candidate.interface == "en0", canonicalGateway(candidate.gateway) == gateway,
              candidate.flags.contains("S"), candidate.flags.contains("G"),
              !candidate.flags.contains("R"), !candidate.flags.contains("B") else {
            throw helperError("未找到唯一匹配的 en0 静态非 scoped 默认路由；未做修改")
        }
        let result = run("/sbin/route", ["-n", "delete", "-inet6", "default", gateway])
        guard result.status == 0 && !result.timedOut else { throw helperError("删除默认直连路由失败") }
        let after = try snapshot()
        guard !after.contains(where: { $0 == candidate }) else { throw helperError("默认直连路由仍然存在") }
    }
}

private func helperError(_ text: String) -> NSError {
    NSError(domain: "WiFiIPv6.Helper", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
}

private func isSecureRootDirectory(_ path: String) -> Bool {
    var info = stat()
    return lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFDIR &&
        info.st_uid == 0 && (info.st_mode & 0o022) == 0
}

private func isTrustedSystemRunDirectory(_ info: stat, daemonGID: gid_t) -> Bool {
    // macOS normally ships /private/var/run as root:daemon 0775. Its
    // privileged daemon group is trusted here only; app-specific directories
    // must still satisfy the stricter no-group-write check above.
    (info.st_mode & S_IFMT) == S_IFDIR && info.st_uid == 0 &&
        (info.st_mode & 0o002) == 0 &&
        ((info.st_mode & 0o020) == 0 || (daemonGID == 1 && info.st_gid == daemonGID))
}

private func hasTrustedRuntimeAncestors() -> Bool {
    guard ["/", "/private", "/private/var"].allSatisfy(isSecureRootDirectory),
          let daemon = getgrnam("daemon"), daemon.pointee.gr_gid == 1 else { return false }
    var info = stat()
    return lstat("/private/var/run", &info) == 0 &&
        isTrustedSystemRunDirectory(info, daemonGID: daemon.pointee.gr_gid)
}

private final class ControlSocket {
    let fd: Int32
    private let lockFD: Int32
    private let path: String

    init(uid: UInt32) throws {
        // /var is a macOS symlink. Use its canonical target for privileged
        // filesystem operations; clients reach the same socket through /var.
        path = "/private" + helperSocketPath(uid: uid)
        let directory = (path as NSString).deletingLastPathComponent
        guard hasTrustedRuntimeAncestors() else { throw helperError("系统运行目录权限不安全") }
        if mkdir(directory, 0o711) != 0 && errno != EEXIST { throw helperError("无法创建控制目录") }
        guard isSecureRootDirectory(directory) else { throw helperError("控制目录权限不安全") }
        guard chmod(directory, 0o711) == 0 else { throw helperError("无法设置控制目录权限") }

        let lockPath = directory + "/helper.lock"
        let locked = open(lockPath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard locked >= 0 else { throw helperError("无法创建控制锁") }
        var info = stat()
        guard fstat(locked, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == 0, info.st_nlink == 1, (info.st_mode & 0o077) == 0 else {
            close(locked); throw helperError("控制锁权限不安全")
        }
        guard flock(locked, LOCK_EX | LOCK_NB) == 0 else { close(locked); throw helperError("已有控制服务在运行") }
        lockFD = locked

        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else { close(locked); throw helperError("无法创建控制 socket") }
        _ = fcntl(socketFD, F_SETFD, FD_CLOEXEC)
        var existing = stat()
        if lstat(path, &existing) == 0 {
            guard (existing.st_mode & S_IFMT) == S_IFSOCK else {
                close(socketFD); close(locked); throw helperError("控制 socket 路径被其他文件占用")
            }
            guard unlink(path) == 0 else { close(socketFD); close(locked); throw helperError("无法清理旧 socket") }
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let utf8 = Array(path.utf8CString)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard utf8.count <= capacity else { close(socketFD); close(locked); throw helperError("Socket 路径过长") }
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            for (index, byte) in utf8.enumerated() { bytes[index] = UInt8(bitPattern: byte) }
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0, chown(path, uid, 0) == 0, chmod(path, 0o600) == 0, listen(socketFD, 8) == 0 else {
            close(socketFD); unlink(path); close(locked); throw helperError("无法准备安全控制 socket")
        }
        fd = socketFD
    }

    deinit { close(fd); unlink(path); flock(lockFD, LOCK_UN); close(lockFD) }
}

private func readRequest(_ fd: Int32) throws -> HelperRequest {
    let deadline = monotonicNow() + clientDeadline
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while monotonicNow() < deadline {
        var event = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let timeout = Int32(max(1, (deadline - monotonicNow()) * 1_000))
        let ready = poll(&event, 1, timeout)
        if ready < 0 && errno == EINTR { continue }
        guard ready > 0 else { throw helperError("请求超时") }
        let count = recv(fd, &buffer, buffer.count, 0)
        guard count > 0 else { throw helperError("请求提前结束") }
        guard data.count + count <= maximumRequestBytes else { throw helperError("请求过大") }
        data.append(contentsOf: buffer.prefix(count))
        if let newline = data.firstIndex(of: 10) {
            guard newline == data.index(before: data.endIndex) else { throw helperError("每个连接只接受一个请求") }
            return try JSONDecoder().decode(HelperRequest.self, from: data[..<newline])
        }
    }
    throw helperError("请求超时")
}

private func sendResponse(_ response: HelperResponse, fd: Int32) {
    guard var data = try? JSONEncoder().encode(response), data.count <= 262_144 else { return }
    data.append(10)
    let deadline = monotonicNow() + clientDeadline
    data.withUnsafeBytes { bytes in
        guard let base = bytes.baseAddress else { return }
        var offset = 0
        while offset < bytes.count && monotonicNow() < deadline {
            var event = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            guard poll(&event, 1, 100) >= 0 else { return }
            let count = send(fd, base.advanced(by: offset), bytes.count - offset, MSG_DONTWAIT)
            if count > 0 { offset += count }
            else if errno != EAGAIN && errno != EINTR { return }
        }
    }
}

private func selfTest() throws {
    func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw helperError("Self-test failed: " + message) }
    }
    var systemDirectory = stat()
    systemDirectory.st_mode = mode_t(S_IFDIR | 0o775)
    systemDirectory.st_uid = 0
    systemDirectory.st_gid = 1
    try check(isTrustedSystemRunDirectory(systemDirectory, daemonGID: 1), "allow standard root:daemon 0775 runtime parent")
    systemDirectory.st_gid = 20
    try check(!isTrustedSystemRunDirectory(systemDirectory, daemonGID: 1), "reject untrusted writable parent group")
    systemDirectory.st_gid = 1; systemDirectory.st_mode = mode_t(S_IFDIR | 0o777)
    try check(!isTrustedSystemRunDirectory(systemDirectory, daemonGID: 1), "reject world-writable runtime parent")
    systemDirectory.st_mode = mode_t(S_IFLNK | 0o775)
    try check(!isTrustedSystemRunDirectory(systemDirectory, daemonGID: 1), "reject symlink runtime parent")
    systemDirectory.st_mode = mode_t(S_IFDIR | 0o775); systemDirectory.st_uid = 501
    try check(!isTrustedSystemRunDirectory(systemDirectory, daemonGID: 1), "reject non-root runtime parent")
    try check(hasTrustedRuntimeAncestors(), "validate actual macOS runtime ancestors without changing permissions")
    let active = "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tinet6 2001:db8::10 prefixlen 64\n\tstatus: active\n"
    let scoped = "gateway: fe80::1%en0\ninterface: en0\nflags: <UP,GATEWAY,IFSCOPE,GLOBAL>\n"
    let sample = "Internet6:\nDestination Gateway Flags Netif Expire\ndefault fe80::dead%en0 UGScg en0\ndefault fe80::1%en0 UGcIg en0\n2001:db8::2 fe80::1%en0 UGHS en0\ndefault fe80::%utun8 UGcIg utun8\n"
    let routes = parseRoutes(sample)
    try check(routes.count == 4, "parse route table")
    try check(currentWiFiGateway(routes: routes, ifconfig: active, scopedRoute: scoped) == "fe80::1%en0", "use scoped router, not stale broad default")
    try check(currentWiFiGateway(routes: routes.filter { !$0.flags.contains("I") }, ifconfig: active, scopedRoute: scoped) == nil, "reject unscoped fallback")
    try check(currentWiFiGateway(routes: routes, ifconfig: active.replacingOccurrences(of: "active", with: "inactive"), scopedRoute: scoped) == nil, "disconnect")
    try check(!hasUsableWiFiIPv6(active.replacingOccurrences(of: "2001:db8::10", with: "fe80::10%en0")), "reject link-local-only Wi-Fi")
    try check(!hasUsableWiFiIPv6(active.replacingOccurrences(of: "prefixlen", with: "tentative prefixlen")), "reject tentative address")
    try check(!hasUsableWiFiIPv6(active.replacingOccurrences(of: "prefixlen", with: "deprecated prefixlen")), "reject deprecated address")
    let oldFingerprint = usableWiFiIPv6Fingerprint(active)
    let newFingerprint = usableWiFiIPv6Fingerprint(active.replacingOccurrences(of: "2001:db8::10", with: "2001:db8:2::10"))
    try check(routeNetworkChanged(oldGateway: "fe80::1%en0", oldFingerprint: oldFingerprint,
                                 gateway: "fe80::1%en0", fingerprint: newFingerprint), "same router with new local prefix refreshes route")
    try check(!routeNetworkChanged(oldGateway: "fe80::1%en0", oldFingerprint: oldFingerprint,
                                  gateway: "fe80::1%en0", fingerprint: oldFingerprint), "unchanged local network preserves route")
    try check(routeNetworkChanged(oldGateway: "fe80::1%en0", oldFingerprint: oldFingerprint,
                                 gateway: nil, fingerprint: nil), "disconnect retires route fingerprint")
    let withTemporary = active.replacingOccurrences(of: "\tstatus:", with: "\tinet6 2001:db8::20 prefixlen 64 temporary\n\tstatus:")
    let reordered = "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tinet6 2001:0db8::20 prefixlen 64 temporary\n\tinet6 2001:db8::10 prefixlen 64\n\tstatus: active\n"
    try check(usableWiFiIPv6Fingerprint(withTemporary) == usableWiFiIPv6Fingerprint(reordered), "fingerprint ignores address order and IPv6 spelling")
    try check(canonicalGateway("fe80::1%en1") == nil && canonicalGateway("::1") == nil, "reject foreign gateway/interface")
    try check(canonicalGateway("fe80::1") == "fe80::1%en0", "link-local scope")
    try check(broadDefaults(routes).count == 1, "distinguish broad default")
    try check(isOwnedMatch(routes[2], address: "2001:db8::2", gateway: "fe80::1%en0"), "recognize owned host route")
    var modified = routes[2]
    modified.flags = "UGH"
    try check(!isOwnedMatch(modified, address: "2001:db8::2", gateway: "fe80::1%en0"), "never own dynamic route")
    modified = routes[2]; modified.interface = "utun8"
    try check(!isOwnedMatch(modified, address: "2001:db8::2", gateway: "fe80::1%en0"), "never own VPN route")
    modified = routes[2]; modified.flags += "I"
    try check(!isOwnedMatch(modified, address: "2001:db8::2", gateway: "fe80::1%en0"), "never own scoped route")
    let stranded = RouteRecord(destination: "2001:db8::2", gateway: "fe80::9%en0", flags: "UGHS", interface: "utun5")
    try check(isStrandedWiFiRoute(stranded, address: "2001:db8::2", currentGateway: "fe80::1%en0", routes: routes), "recover stranded Wi-Fi host after network change")
    try check(!isStrandedWiFiRoute(stranded, address: "2001:db8::3", currentGateway: "fe80::1%en0", routes: routes), "never recover an unrelated destination")
    try check(!isStrandedWiFiRoute(stranded, address: "2001:db8::2", currentGateway: "fe80::9%en0", routes: routes), "do not replace current gateway")
    var vpn = stranded; vpn.gateway = "fe80::9%utun5"
    try check(!isStrandedWiFiRoute(vpn, address: "2001:db8::2", currentGateway: "fe80::1%en0", routes: routes), "preserve real VPN route")
    vpn = stranded; vpn.interface = "en0"
    try check(!isStrandedWiFiRoute(vpn, address: "2001:db8::2", currentGateway: "fe80::1%en0", routes: routes), "preserve existing Wi-Fi route")
    vpn = stranded; vpn.flags += "I"
    try check(!isStrandedWiFiRoute(vpn, address: "2001:db8::2", currentGateway: "fe80::1%en0", routes: routes), "preserve scoped route")
    let oldDefault = RouteRecord(destination: "default", gateway: "fe80::9%en0", flags: "UGcIg", interface: "en0")
    try check(!isStrandedWiFiRoute(stranded, address: "2001:db8::2", currentGateway: "fe80::1%en0", routes: routes + [oldDefault]), "preserve still available gateway")
    let controller = RouteController()
    try controller.setAddresses(["2001:db8::1", "2001:0db8::1"])
    do { try controller.setAddresses(["::/0"]); throw helperError("range unexpectedly accepted") }
    catch { try check(error.localizedDescription.contains("无效"), "reject ranges") }
    do { try controller.setAddresses(Array(repeating: "2001:db8::1", count: 257)); throw helperError("limit unexpectedly accepted") }
    catch { try check(error.localizedDescription.contains("256"), "enforce count limit") }
    var pair: [Int32] = [-1, -1]
    try check(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0, "create transport test sockets")
    defer { close(pair[0]); close(pair[1]) }
    let requestData = Data("{\"command\":\"status\"}\n".utf8)
    requestData.withUnsafeBytes { bytes in _ = send(pair[0], bytes.baseAddress, bytes.count, 0) }
    let request = try readRequest(pair[1])
    try check(request.command == "status" && request.addresses == nil, "decode newline-framed request")
    let multiple = Data("{\"command\":\"status\"}\n{}\n".utf8)
    multiple.withUnsafeBytes { bytes in _ = send(pair[0], bytes.baseAddress, bytes.count, 0) }
    do { _ = try readRequest(pair[1]); throw helperError("extra request unexpectedly accepted") }
    catch { try check(error.localizedDescription.contains("一个请求"), "reject multiple requests per connection") }
    print("Helper self-tests passed (routing parser, ownership, input limits and socket framing; no routes changed).")
}

@main
private enum HelperMain {
    static func main() {
        if CommandLine.arguments == [CommandLine.arguments[0], "--self-test"] {
            do { try selfTest(); exit(0) }
            catch { fputs(error.localizedDescription + "\n", stderr); exit(1) }
        }
        guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--uid",
              let uid = UInt32(CommandLine.arguments[2]), uid > 0, getpwuid(uid) != nil, geteuid() == 0 else {
            fputs("Usage: WiFiIPv6Helper --uid <non-root uid> (root required), or --self-test\n", stderr)
            exit(64)
        }
        signal(SIGPIPE, SIG_IGN)
        signal(SIGTERM) { _ in helperExitRequested = 1 }
        signal(SIGINT) { _ in helperExitRequested = 1 }
        signal(SIGHUP) { _ in helperExitRequested = 1 }
        do {
            let socket = try ControlSocket(uid: uid)
            let controller = RouteController()
            defer { controller.cleanup(); _ = socket }
            var lastAuthorizedRequest = monotonicNow()
            var lastPoll: TimeInterval = 0
            while helperExitRequested == 0 && monotonicNow() - lastAuthorizedRequest < heartbeatTimeout {
                if monotonicNow() - lastPoll >= 3 {
                    controller.reconcile()
                    lastPoll = monotonicNow()
                }
                var event = pollfd(fd: socket.fd, events: Int16(POLLIN), revents: 0)
                guard poll(&event, 1, 250) > 0, event.revents & Int16(POLLIN) != 0 else { continue }
                let client = accept(socket.fd, nil, nil)
                guard client >= 0 else { continue }
                _ = fcntl(client, F_SETFD, FD_CLOEXEC)
                var peerUID: uid_t = UInt32.max
                var peerGID: gid_t = UInt32.max
                guard getpeereid(client, &peerUID, &peerGID) == 0, peerUID == uid || peerUID == 0 else {
                    close(client); continue
                }
                var shouldStop = false
                do {
                    let request = try readRequest(client)
                    switch request.command {
                    case "status":
                        guard request.addresses == nil && request.gateway == nil else { throw helperError("status 不接受参数") }
                    case "enable", "update":
                        guard let addresses = request.addresses, request.gateway == nil else { throw helperError("缺少白名单地址") }
                        try controller.setAddresses(addresses)
                        if request.command == "enable" { controller.enabled = true }
                        controller.reconcile()
                    case "disable", "stop":
                        guard request.addresses == nil && request.gateway == nil else { throw helperError("不接受额外参数") }
                        controller.enabled = false
                        controller.reconcile()
                        shouldStop = request.command == "stop"
                    case "removeBroadDefault":
                        guard let gateway = request.gateway, request.addresses == nil else { throw helperError("缺少待删除的网关") }
                        try controller.removeBroadDefault(gateway: gateway)
                        controller.reconcile()
                    default: throw helperError("不支持的命令")
                    }
                    lastAuthorizedRequest = monotonicNow()
                    sendResponse(HelperResponse(ok: controller.status.error == nil,
                        message: controller.status.error ?? "OK", status: controller.status), fd: client)
                } catch {
                    sendResponse(HelperResponse(ok: false, message: error.localizedDescription, status: controller.status), fd: client)
                }
                close(client)
                if shouldStop { break }
            }
        } catch { fputs(error.localizedDescription + "\n", stderr); exit(1) }
    }
}
