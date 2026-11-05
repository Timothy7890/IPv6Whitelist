import Foundation
import Darwin

struct WeChatDiscoverySettings: Codable {
    var enabled = false
    var excludedAddresses: Set<String> = []
}

struct WeChatScan {
    var processCount: Int
    var addresses: Set<String>
    var ipv4Connections = 0
    var proxyConnections = 0
}

enum WeChatDiscovery {
    static func isWeChatPath(_ path: String, home: String = NSHomeDirectory()) -> Bool {
        ["/Applications/WeChat.app/Contents/", home + "/Applications/WeChat.app/Contents/"]
            .contains { path.hasPrefix($0) && !path.contains("/../") }
    }

    // Automatic discovery is intentionally stricter than the manual address editor.
    static func publicAddress(_ value: String) -> String? {
        guard let address = canonicalIPv6(value) else { return nil }
        var parsed = in6_addr()
        guard address.withCString({ inet_pton(AF_INET6, $0, &parsed) }) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: parsed) { Array($0) }
        guard bytes[0] & 0xe0 == 0x20 else { return nil } // Global unicast 2000::/3.
        guard !address.hasPrefix("2001:db8:"), !address.hasPrefix("2002:"),
              !(bytes[0] == 0x20 && bytes[1] == 1 && bytes[2] == 0 && bytes[3] == 0) else { return nil } // Documentation / transition addresses.
        return address
    }

    static func parse(_ output: String, allowedPIDs: Set<Int32>) -> WeChatScan {
        var result = WeChatScan(processCount: allowedPIDs.count, addresses: [])
        var allowed = false
        for line in output.split(separator: "\n") {
            if line.first == "p" {
                allowed = Int32(line.dropFirst()).map { allowedPIDs.contains($0) } ?? false
            } else if allowed, line.first == "n", let arrow = line.range(of: "->") {
                let remote = String(line[arrow.upperBound...])
                if remote.hasPrefix("["), let end = remote.firstIndex(of: "]") {
                    let literal = String(remote[remote.index(after: remote.startIndex)..<end])
                    if let address = publicAddress(literal) { result.addresses.insert(address) }
                    else if literal == "::1" { result.proxyConnections += 1 }
                } else if remote.hasPrefix("127.") {
                    result.proxyConnections += 1
                } else if remote.split(separator: ":").first?.contains(".") == true {
                    result.ipv4Connections += 1
                }
            }
        }
        return result
    }

    static func scan() throws -> WeChatScan {
        let ps = LocalCommand.run("/bin/ps", ["-axo", "pid=,comm="], timeout: 3)
        guard ps.code == 0 else { throw failure("无法读取微信进程：\(ps.output)") }
        var processes: [Int32: String] = [:]
        for line in ps.output.split(separator: "\n") {
            let parts = line.split(maxSplits: 1, whereSeparator: \.isWhitespace)
            guard parts.count == 2, let pid = Int32(parts[0]) else { continue }
            let path = String(parts[1]).trimmingCharacters(in: .whitespaces)
            if isWeChatPath(path), processPath(pid) == path { processes[pid] = path }
        }
        guard !processes.isEmpty else { return WeChatScan(processCount: 0, addresses: []) }
        guard processes.count <= 512 else { throw failure("微信进程数量异常，本轮未更新") }
        let result = LocalCommand.run("/usr/sbin/lsof", ["-nP", "-a", "-p",
            processes.keys.sorted().map(String.init).joined(separator: ","), "-i", "-FpcfnT"], timeout: 4)
        // Exit 1 with empty output means no matching sockets, not a broken scan.
        guard result.code == 0 || (result.code == 1 && result.output.isEmpty),
              !result.output.contains("lsof:") else {
            throw failure("读取微信连接失败：\(result.output.prefix(300))")
        }
        let valid = Set(processes.compactMap { pid, path in processPath(pid) == path ? pid : nil })
        return parse(result.output, allowedPIDs: valid)
    }

    private static func processPath(_ pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let size = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        return size > 0 ? String(cString: buffer) : nil
    }

    private static func failure(_ message: String) -> NSError {
        NSError(domain: "WeChatDiscovery", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

struct WeChatMerge {
    var entries: [WhitelistEntry]
    var added = 0
    var removed = 0
    var skipped = 0
}

enum WeChatAddressPolicy {
    static let lifetime: TimeInterval = 7 * 24 * 60 * 60
    static let automaticLimit = 128
    static let totalLimit = 256

    static func merge(_ current: [WhitelistEntry], observed: Set<String>,
                      excluded: Set<String>, now: Date) -> WeChatMerge {
        let observed = Set(observed.compactMap(WeChatDiscovery.publicAddress))
        var result = WeChatMerge(entries: current)
        result.entries.removeAll { entry in
            entry.isWeChatAutomatic && entry.enabled && !observed.contains(entry.address) &&
                now.timeIntervalSince(entry.lastSeen ?? entry.firstSeen ?? now) >= lifetime
        }
        result.removed = current.count - result.entries.count
        for index in result.entries.indices where result.entries[index].isWeChatAutomatic && observed.contains(result.entries[index].address) {
            result.entries[index].lastSeen = now
        }
        for address in observed.sorted() where !excluded.contains(address) && !result.entries.contains(where: { $0.address == address }) {
            if result.entries.count >= totalLimit || result.entries.filter(\.isWeChatAutomatic).count >= automaticLimit {
                // Never evict manual, disabled, or currently observed addresses.
                let victim = result.entries.indices.filter {
                    let e = result.entries[$0]
                    return e.isWeChatAutomatic && e.enabled && !observed.contains(e.address)
                }.min { (result.entries[$0].lastSeen ?? .distantPast) < (result.entries[$1].lastSeen ?? .distantPast) }
                if let victim { result.entries.remove(at: victim); result.removed += 1 }
            }
            guard result.entries.count < totalLimit,
                  result.entries.filter(\.isWeChatAutomatic).count < automaticLimit else { result.skipped += 1; continue }
            result.entries.append(WhitelistEntry(address: address, name: "微信自动 · \(address)",
                sources: ["微信自动发现"], automaticSource: "wechat", firstSeen: now, lastSeen: now))
            result.added += 1
        }
        return result
    }
}
