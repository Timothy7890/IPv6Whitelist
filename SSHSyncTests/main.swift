import Foundation

func require(_ condition: @autoclosure () throws -> Bool, _ message: String) {
    do {
        if try !condition() { fatalError(message) }
    } catch {
        fatalError("\(message): \(error)")
    }
}

func sshG(_ config: URL, host: String) throws -> [String: String] {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
    process.arguments = ["-G", "-F", config.path, host]
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = Pipe()
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    require(process.terminationStatus == 0, "ssh -G failed")
    var values: [String: String] = [:]
    for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
        let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
        if parts.count == 2 { values[parts[0]] = parts[1] }
    }
    return values
}

let json = """
[
 {"id":"t1","key_id":"k1","client_label":"WIN-5070","client_address":"1.1.1.1:1","local_address":"127.0.0.1:22",
  "public_address":"8.136.105.252:20091","active_connections":0,"created_at":"2026-11-05T04:15:43.123456Z",
  "device_address_info":[
   {"ip":"192.168.31.254","kind":"lan-ipv4","label":"小米局域网","primary":true},
   {"ip":"240e:390:705c:3000::539","kind":"public-ipv6","label":"公网 IPv6-短","primary":true},
   {"ip":"240e:390:705c:3000:6c5f:1aa0:fc82:647b","kind":"public-ipv6","label":"公网 IPv6","primary":false}]},
 {"id":"t2","key_id":"k1","client_label":"WIN-5070","client_address":"1.1.1.1:1","local_address":"127.0.0.1:15900",
  "public_address":"8.136.105.252:20012","active_connections":0,"created_at":"2026-11-05T04:15:45Z"},
 {"id":"t3","key_id":"k2","client_label":"LXZ-606","client_address":"2.2.2.2:2","local_address":"127.0.0.1:22",
  "public_address":"8.136.105.252:20020","active_connections":0,"created_at":"2026-11-05T04:04:39Z",
  "device_address_info":[
   {"ip":"10.195.66.203","kind":"lan-ipv4","label":"浙大局域网","primary":true},
   {"ip":"198.18.0.1","kind":"proxy","label":"代理","primary":false}]},
 {"id":"t4","key_id":"","client_label":"no key","client_address":"3.3.3.3:3","local_address":"127.0.0.1:22",
  "public_address":"8.136.105.252:20030","active_connections":0,"created_at":"2026-11-05T04:04:39Z"}
]
"""
let tunnels = try JSONDecoder().decode([NetbridgeTunnel].self, from: Data(json.utf8))
let devices = groupNetbridgeDevices(tunnels)
require(devices.map(\.label) == ["LXZ-606", "WIN-5070"], "devices are grouped by key and keyless ones skipped")
let lxz = devices[0], win = devices[1]
require(win.forwards.map(\.localAddress) == ["127.0.0.1:22", "127.0.0.1:15900"], "forwards are merged and sorted")

func mapping(_ device: NetbridgeDevice, _ alias: String, _ policy: SSHAddressPolicy, forward: String? = nil) -> SSHMapping {
    SSHMapping(keyID: device.keyID, deviceLabel: device.label, hostAlias: alias, policy: policy, forwardTarget: forward)
}
require(resolveSSHTarget(mapping(lxz, "a", .lanIPv4), device: lxz) == SSHTarget(hostName: "10.195.66.203"), "LAN IPv4")
require(resolveSSHTarget(mapping(lxz, "a", .publicIPv6), device: lxz) == nil, "no IPv6 reported")
require(resolveSSHTarget(mapping(win, "a", .publicIPv6), device: win) == SSHTarget(hostName: "240e:390:705c:3000::539"), "primary IPv6 only")
require(resolveSSHTarget(mapping(win, "a", .tunnelEntry, forward: "127.0.0.1:22"), device: win) == SSHTarget(hostName: "8.136.105.252", port: 20091), "tunnel entry")
require(resolveSSHTarget(mapping(win, "a", .tunnelEntry, forward: "127.0.0.1:9"), device: win) == nil, "unknown forward")
// Proxy addresses are never picked even if a report marks them primary.
var proxied = lxz
proxied.addresses = [NetbridgeAddress(ip: "198.18.0.1", kind: "proxy", label: "代理", primary: true)]
require(resolveSSHTarget(mapping(proxied, "a", .lanIPv4), device: proxied) == nil, "proxy not used")

// Reported values cannot inject ssh options.
var injected = lxz
injected.addresses = [NetbridgeAddress(ip: "1.2.3.4\n    ProxyCommand touch /tmp/x", kind: "lan-ipv4", label: "x", primary: true)]
require(resolveSSHTarget(mapping(injected, "a", .lanIPv4), device: injected) == nil, "address injection")
require(parseNetbridgeEntry("evil host\nProxyCommand x:22") == nil, "entry injection")
require(parseNetbridgeEntry("-oProxyCommand=x:22") == nil, "leading dash")
require(parseNetbridgeEntry("[2001:db8::1]:2222") == SSHTarget(hostName: "2001:db8::1", port: 2222), "bracketed IPv6")
require(parseNetbridgeEntry("host.example:99999") == nil, "bad port")
for bad in ["", "a b", "a\nHost *", "*", "a?", "!a", "-oX", "a#b", "a,b", "%h"] { require(!isSafeSSHAlias(bad), "alias accepted: \(bad)") }
for good in ["LXZ-606", "2004-zju-ipv6", "Starry_ali", "host.name", "服务器"] { require(isSafeSSHAlias(good), "alias refused: \(good)") }
var unsafe = mapping(lxz, "bad alias", .lanIPv4); unsafe.applied = SSHTarget(hostName: "1.1.1.1")
var unsafeTarget = mapping(lxz, "ok", .lanIPv4); unsafeTarget.applied = SSHTarget(hostName: "1 2\nProxyCommand x")
let rendered = renderDynamicSSHConfig([unsafe, unsafeTarget])
require(!rendered.contains("Host ") && !rendered.contains("ProxyCommand"), "unsafe values are not rendered")

// Controller URLs: the token only goes over HTTPS.
require(try netbridgeTunnelsURL(controller: " https://nbg.example.com/x?y=1 ").absoluteString == "https://nbg.example.com/v1/tunnels", "URL")
for bad in ["http://nbg.example.com", "nbg.example.com", "", "ftp://a"] {
    require((try? netbridgeTunnelsURL(controller: bad)) == nil, "URL accepted: \(bad)")
}

// SOCKS5 proxy settings.
require(try parseSOCKSProxy("") == nil, "empty proxy means direct")
require(try parseSOCKSProxy(" 127.0.0.1:1085 ") == SOCKSProxy(host: "127.0.0.1", port: 1085), "host and port")
require(try parseSOCKSProxy("1085") == SOCKSProxy(host: "127.0.0.1", port: 1085), "bare port")
require(try parseSOCKSProxy("socks5://localhost:1085") == SOCKSProxy(host: "localhost", port: 1085), "scheme")
for bad in ["127.0.0.1", "127.0.0.1:99999", "a b:1085", "70000"] {
    require((try? parseSOCKSProxy(bad)) == nil, "proxy accepted: \(bad)")
}

require(socksProxyPresets.count == Set(socksProxyPresets.map(\.port)).count, "preset ports are unique")
require(socksProxyPreset(matching: "127.0.0.1:1085")?.name == "PYX-606", "preset by address")
require(socksProxyPreset(matching: "1091")?.name == "mybox-abyss", "preset by bare port")
require(socksProxyPreset(matching: "localhost:1081")?.name == "LXZ-606", "preset by localhost")
require(socksProxyPreset(matching: "192.0.2.1:1085") == nil, "another machine is not a preset")
require(socksProxyPreset(matching: "") == nil, "direct is not a preset")
for preset in socksProxyPresets {
    require(try parseSOCKSProxy(preset.address) == SOCKSProxy(host: "127.0.0.1", port: preset.port), "preset parses")
}

// Filtering.
let filterHosts = [
    SSHEffectiveHost(alias: "LXZ-606", hostName: "10.195.66.203"),
    SSHEffectiveHost(alias: "WIN-5070-ipv6", hostName: "240e:390:705c:3000::539"),
    SSHEffectiveHost(alias: "WIN-5070-frp", hostName: "8.136.105.252", port: 20091),
]
func aliases(_ query: String) -> [String] { filterSSHHosts(filterHosts, query: query).map(\.alias) }
require(aliases("").count == 3 && aliases("   ").count == 3, "empty query keeps all")
require(aliases("lxz") == ["LXZ-606"], "case-insensitive alias")
require(aliases("10.195") == ["LXZ-606"], "by address")
require(aliases("20091") == ["WIN-5070-frp"], "by port")
require(aliases("ipv6 win") == ["WIN-5070-ipv6"], "all words in any order")
require(aliases("lxz ipv6").isEmpty, "every word must match")
let filterMappings = [
    SSHMapping(keyID: "k", deviceLabel: "NAS", hostAlias: "home", policy: .publicIPv6),
    SSHMapping(keyID: "k", deviceLabel: "WIN", hostAlias: "work", policy: .lanIPv4, applied: SSHTarget(hostName: "10.0.0.1")),
]
require(filterSSHMappings(filterMappings, query: "nas").map(\.hostAlias) == ["home"], "mapping by device")
require(filterSSHMappings(filterMappings, query: "10.0").map(\.hostAlias) == ["work"], "mapping by address")
require(filterSSHMappings(filterMappings, query: "").count == 2, "mapping empty query")

// Files, checked against the real ssh parser.
let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("ssh-sync-tests-\(UUID().uuidString)")
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: directory) }
let paths = SSHSyncPaths(config: directory.appendingPathComponent("config"),
                         dynamic: directory.appendingPathComponent("config.d/netbridge-dynamic"))
let original = """
Host clawd
    HostName 192.0.2.9
    Port 2222

Host LXZ-606
    HostName 192.0.2.1
    User huawei
    ProxyJump clawd
# 注释保留
Host WIN
    HostName 192.0.2.2
    Port 22
"""
try Data(original.utf8).write(to: paths.config)
try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: paths.config.path)
require(readSSHIncludeStatus(paths: paths) == .missing, "starts missing")

let backup = try installSSHInclude(paths: paths, now: Date(timeIntervalSince1970: 0))
require(try backup != nil && (try String(contentsOf: backup!, encoding: .utf8)) == original, "backup keeps the original")
let installed = try String(contentsOf: paths.config, encoding: .utf8)
require(installed.hasSuffix(original) && installed.contains(paths.includeLine), "original bytes preserved")
require((try FileManager.default.attributesOfItem(atPath: paths.config.path)[.posixPermissions] as? Int) == 0o640, "permissions kept")
require(readSSHIncludeStatus(paths: paths) == .active, "active after install")
require(try installSSHInclude(paths: paths) == nil && (try String(contentsOf: paths.config, encoding: .utf8)) == installed, "install is idempotent")

// Before anything is generated, ssh must still work with the missing file.
require(try sshG(paths.config, host: "LXZ-606")["hostname"] == "192.0.2.1", "missing include file is harmless")

var lan = mapping(lxz, "LXZ-606", .lanIPv4); lan.applied = resolveSSHTarget(lan, device: lxz)
var entry = mapping(win, "WIN", .tunnelEntry, forward: "127.0.0.1:22"); entry.applied = resolveSSHTarget(entry, device: win)
require(try writeDynamicSSHConfig(renderDynamicSSHConfig([lan, entry]), paths: paths), "first write changes")
require(try !writeDynamicSSHConfig(renderDynamicSSHConfig([entry, lan]), paths: paths), "same content is not rewritten")
require((try FileManager.default.attributesOfItem(atPath: paths.dynamic.path)[.posixPermissions] as? Int) == 0o600, "generated file is private")

let lxzConfig = try sshG(paths.config, host: "LXZ-606")
require(lxzConfig["hostname"] == "10.195.66.203", "generated HostName wins")
require(lxzConfig["user"] == "huawei" && lxzConfig["proxyjump"] == "clawd", "main config options still apply")
require(lxzConfig["hostkeyalias"] == "netbridge-lxz-606", "HostKeyAlias (ssh lowercases it)")
let winConfig = try sshG(paths.config, host: "WIN")
require(winConfig["hostname"] == "8.136.105.252" && winConfig["port"] == "20091", "generated Port wins")
let untouched = try sshG(paths.config, host: "clawd")
require(untouched["hostname"] == "192.0.2.9" && untouched["port"] == "2222" && untouched["hostkeyalias"] == nil, "other hosts untouched")

// The app's own parser agrees with ssh.
let effective = Dictionary(uniqueKeysWithValues: SSHImporter.effectiveHosts(configPath: paths.config.path).map { ($0.alias, $0) })
require(effective["LXZ-606"]?.hostName == "10.195.66.203", "effective HostName")
require(effective["WIN"]?.display == "8.136.105.252:20091", "effective port")
require(effective["clawd"]?.display == "192.0.2.9:2222", "hosts after the include are still evaluated")

// ProxyJump: inherit, direct, or a chosen Host. Checked with the real ssh.
var jumpMapping = mapping(lxz, "LXZ-606", .lanIPv4)
jumpMapping.applied = SSHTarget(hostName: "10.195.66.203")
try writeDynamicSSHConfig(renderDynamicSSHConfig([jumpMapping]), paths: paths)
require(try sshG(paths.config, host: "LXZ-606")["proxyjump"] == "clawd", "inherit keeps the main config's jump")
jumpMapping.proxyJump = sshProxyJumpNone
try writeDynamicSSHConfig(renderDynamicSSHConfig([jumpMapping]), paths: paths)
require(try sshG(paths.config, host: "LXZ-606")["proxyjump"] == nil, "direct overrides the main config's jump")
require(try sshG(paths.config, host: "LXZ-606")["hostname"] == "10.195.66.203", "direct keeps the address")
jumpMapping.proxyJump = "WIN"
try writeDynamicSSHConfig(renderDynamicSSHConfig([jumpMapping]), paths: paths)
require(try sshG(paths.config, host: "LXZ-606")["proxyjump"] == "WIN", "chosen jump overrides the main config's")
require(try sshG(paths.config, host: "LXZ-606")["user"] == "huawei", "other options still apply")
require(SSHImporter.effectiveHosts(configPath: paths.config.path).first { $0.alias == "LXZ-606" }?.proxyJump == "WIN", "parser agrees with ssh")

// A jump can be set before any address is known, and keeps the main HostName.
var jumpOnly = mapping(win, "WIN", .publicIPv6)
jumpOnly.proxyJump = "clawd"
try writeDynamicSSHConfig(renderDynamicSSHConfig([jumpOnly]), paths: paths)
let jumpOnlyConfig = try sshG(paths.config, host: "WIN")
require(jumpOnlyConfig["proxyjump"] == "clawd" && jumpOnlyConfig["hostname"] == "192.0.2.2" && jumpOnlyConfig["hostkeyalias"] == nil, "jump without address")

// It also wins over a ProxyCommand later in the main config.
let commandConfig = directory.appendingPathComponent("command-config")
try Data("\(paths.includeLine)\nHost WIN\n  ProxyCommand nc %h %p\n".utf8).write(to: commandConfig)
var overCommand = mapping(win, "WIN", .publicIPv6)
overCommand.proxyJump = sshProxyJumpNone
try writeDynamicSSHConfig(renderDynamicSSHConfig([overCommand]), paths: paths)
require(try sshG(commandConfig, host: "WIN")["proxycommand"] == nil, "direct wins over ProxyCommand")
try writeDynamicSSHConfig(renderDynamicSSHConfig([]), paths: paths)
require(SSHImporter.effectiveHosts(configPath: commandConfig.path).first { $0.alias == "WIN" }?.usesProxyCommand == true, "ProxyCommand detected")

// Unsafe jump values are never written.
var badJump = mapping(lxz, "LXZ-606", .lanIPv4)
badJump.proxyJump = "a\nProxyCommand x"
require(!renderDynamicSSHConfig([badJump]).contains("ProxyCommand"), "jump injection")
require(!isSafeSSHProxyJump("a,b") && !isSafeSSHProxyJump("-oX") && isSafeSSHProxyJump("none") && isSafeSSHProxyJump("PYX-606"), "jump validation")

// Cycles are refused.
let cycleHosts = [
    SSHEffectiveHost(alias: "A", hostName: "192.0.2.1"),
    SSHEffectiveHost(alias: "B", hostName: "192.0.2.2", proxyJump: "A"),
    SSHEffectiveHost(alias: "C", hostName: "192.0.2.3", proxyJump: "user@B:22,D"),
    SSHEffectiveHost(alias: "D", hostName: "192.0.2.4"),
]
require(proxyJumpCreatesCycle(alias: "A", jump: "A", hosts: cycleHosts, mappings: []), "self jump")
require(proxyJumpCreatesCycle(alias: "A", jump: "B", hosts: cycleHosts, mappings: []), "two hosts")
require(proxyJumpCreatesCycle(alias: "A", jump: "C", hosts: cycleHosts, mappings: []), "through user@host:port hops")
require(!proxyJumpCreatesCycle(alias: "A", jump: "D", hosts: cycleHosts, mappings: []), "no cycle")
require(!proxyJumpCreatesCycle(alias: "A", jump: "none", hosts: cycleHosts, mappings: []), "direct is never a cycle")
var freed = mapping(lxz, "B", .lanIPv4); freed.proxyJump = sshProxyJumpNone
require(!proxyJumpCreatesCycle(alias: "A", jump: "B", hosts: cycleHosts, mappings: [freed]), "a mapping's choice replaces the config's")
var looped = mapping(lxz, "D", .lanIPv4); looped.proxyJump = "A"
require(proxyJumpCreatesCycle(alias: "A", jump: "D", hosts: cycleHosts, mappings: [looped]), "a mapping can create the cycle")

// Settings saved by the previous version still load.
let oldMapping = try JSONDecoder().decode(SSHMapping.self, from: Data(#"{"id":"00000000-0000-0000-0000-000000000001","keyID":"k","deviceLabel":"d","hostAlias":"h","policy":"lanIPv4"}"#.utf8))
require(oldMapping.proxyJump == nil, "old mapping decodes as inherit")

// Keyboard highlight.
let rows = ["a", "b", "c"]
require(movedHighlight(current: nil, items: rows, delta: 1) == "a", "down enters the list")
require(movedHighlight(current: nil, items: rows, delta: -1) == nil, "up stays in the search field")
require(movedHighlight(current: "a", items: rows, delta: 1) == "b", "down moves")
require(movedHighlight(current: "b", items: rows, delta: -1) == "a", "up moves")
require(movedHighlight(current: "a", items: rows, delta: -1) == nil, "up from the first returns to the field")
require(movedHighlight(current: "c", items: rows, delta: 1) == "c", "down stops at the end")
require(movedHighlight(current: "gone", items: rows, delta: 1) == "a", "a row filtered away restarts at the top")
require(movedHighlight(current: "a", items: [], delta: 1) == nil, "no rows")

// Removing every mapping falls back to the main config.
try writeDynamicSSHConfig(renderDynamicSSHConfig([]), paths: paths)
require(try sshG(paths.config, host: "LXZ-606")["hostname"] == "192.0.2.1", "fallback after removal")

// An Include placed under a Host is reported, not rewritten.
let misplaced = directory.appendingPathComponent("misplaced")
let body = "Host a\n  HostName 192.0.2.3\n\(paths.includeLine)\n"
try Data(body.utf8).write(to: misplaced)
var misplacedPaths = paths
misplacedPaths.config = misplaced
require(readSSHIncludeStatus(paths: misplacedPaths) == .misplaced, "misplaced detected")
require(try (try? installSSHInclude(paths: misplacedPaths)) == nil && (try String(contentsOf: misplaced, encoding: .utf8)) == body, "misplaced not modified")

// A config that is not UTF-8 is left alone.
let binary = directory.appendingPathComponent("binary")
try Data([0xff, 0xfe, 0x00, 0x41]).write(to: binary)
var binaryPaths = paths
binaryPaths.config = binary
require(try (try? installSSHInclude(paths: binaryPaths)) == nil && (try Data(contentsOf: binary)) == Data([0xff, 0xfe, 0x00, 0x41]), "binary not modified")

// A symlinked config stays a symlink.
let target = directory.appendingPathComponent("real-config")
try Data("Host a\n".utf8).write(to: target)
let link = directory.appendingPathComponent("link-config")
try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
var linkPaths = paths
linkPaths.config = link
try installSSHInclude(paths: linkPaths)
require((try FileManager.default.destinationOfSymbolicLink(atPath: link.path)).hasSuffix("real-config"), "symlink kept")
require((try String(contentsOf: target, encoding: .utf8)).contains(paths.includeLine), "symlink target updated")

// Live read against the real Controller: token comes from the environment.
if let token = ProcessInfo.processInfo.environment["NETBRIDGE_LIVE_TOKEN"] {
    let socks = ProcessInfo.processInfo.environment["NETBRIDGE_LIVE_SOCKS"] ?? ""
    print("route:", socks.isEmpty ? "direct" : socks)
    let live = groupNetbridgeDevices(try await fetchNetbridgeTunnels(controller: "https://nbg.xingxingdiandian.xyz", token: token, socksProxy: socks))
    for device in live {
        print(device.label, device.addresses.filter(\.primary).map(\.ip), device.forwards.map(\.publicAddress))
    }
    let denied = try? await fetchNetbridgeTunnels(controller: "https://nbg.xingxingdiandian.xyz", token: "wrong-token-wrong-token", socksProxy: socks)
    require(denied == nil, "wrong token refused")
    if !socks.isEmpty {
        // A dead proxy must fail, which proves requests really go through the setting.
        let dead = try? await fetchNetbridgeTunnels(controller: "https://nbg.xingxingdiandian.xyz", token: token, socksProxy: "127.0.0.1:9")
        require(dead == nil, "dead proxy was bypassed")
    }
}
print("SSH sync tests passed")
