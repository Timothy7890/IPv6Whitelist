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

// One device forwarding through two nodes.
let multiNodeJSON = """
[
 {"id":"a","node_id":"ali","key_id":"k9","client_label":"Starry","client_address":"1.1.1.1:1","local_address":"127.0.0.1:22",
  "public_address":"8.136.105.252:20011","active_connections":0,"created_at":"2026-11-05T04:15:43Z"},
 {"id":"h","node_id":"home-1","key_id":"k9","client_label":"Starry","client_address":"1.1.1.1:2","local_address":"127.0.0.1:22",
  "public_address":"home-1.xin0930.xyz:20100","access_address":"[240e:390:7052:7ce0::1]:20100",
  "active_connections":0,"created_at":"2026-11-05T04:15:44Z"},
 {"id":"s","node_id":"home-2","key_id":"k9","client_label":"Starry","client_address":"1.1.1.1:3","local_address":"127.0.0.1:22",
  "public_address":"home-2.xin0930.xyz:20200","access_address":"[240e:390:7052:7ce0::2]:20200","access_stale":true,
  "active_connections":0,"created_at":"2026-11-05T04:15:45Z"},
 {"id":"n","node_id":"home-3","key_id":"k9","client_label":"Starry","client_address":"1.1.1.1:4","local_address":"127.0.0.1:22",
  "public_address":"home-3.xin0930.xyz:20300","access_stale":true,"active_connections":0,"created_at":"2026-11-05T04:15:46Z"}
]
"""
let starry = groupNetbridgeDevices(try JSONDecoder().decode([NetbridgeTunnel].self, from: Data(multiNodeJSON.utf8)))[0]
require(starry.forwards.map(\.nodeID) == ["ali", "home-1", "home-2", "home-3"], "the same target on two nodes stays apart")
require(Set(starry.forwards.map(\.id)).count == 4, "forward ids are unique across nodes")
func onNode(_ node: String?) -> SSHMapping {
    SSHMapping(keyID: "k9", deviceLabel: "Starry", hostAlias: "s", policy: .tunnelEntry, forwardTarget: "127.0.0.1:22", forwardNode: node)
}
require(resolveSSHTarget(onNode("ali"), device: starry) == SSHTarget(hostName: "8.136.105.252", port: 20011), "ali entry")
require(resolveSSHTarget(onNode("home-1"), device: starry) == SSHTarget(hostName: "240e:390:7052:7ce0::1", port: 20100), "resolved IPv6 is used, not the domain")
require(resolveSSHTarget(onNode("home-2"), device: starry) == SSHTarget(hostName: "240e:390:7052:7ce0::2", port: 20200), "last known address stays usable")
require(starry.forwards[2].stale && starry.forwards[2].title.contains("解析失败"), "a failed lookup is shown")
require(resolveSSHTarget(onNode("home-3"), device: starry) == SSHTarget(hostName: "home-3.xin0930.xyz", port: 20300), "unresolved falls back to the node's own entry")
require(resolveSSHTarget(onNode("gone"), device: starry) == nil, "a node that is down does not move the Host elsewhere")
require(starry.forwards[1].title == "home-1 · 22 → [240e:390:7052:7ce0::1]:20100", "entry title")
var oldEntry = onNode(nil)
let migrated = assigningDefaultForwardNode([oldEntry, SSHMapping(keyID: "k", deviceLabel: "d", hostAlias: "lan", policy: .lanIPv4)])
require(migrated[0].forwardNode == "ali", "old tunnel mappings belong to ali")
require(migrated[1].forwardNode == nil, "other mappings are left alone")
oldEntry.forwardNode = "home-1"
require(assigningDefaultForwardNode([oldEntry])[0].forwardNode == "home-1", "a chosen node is kept")
let oldSaved = #"{"id":"00000000-0000-0000-0000-000000000001","keyID":"k","deviceLabel":"d","hostAlias":"a","policy":"tunnelEntry","forwardTarget":"127.0.0.1:22"}"#
require(try JSONDecoder().decode(SSHMapping.self, from: Data(oldSaved.utf8)).forwardNode == nil, "settings from before nodes still load")
var ipv6Entry = onNode("home-1"); ipv6Entry.applied = resolveSSHTarget(ipv6Entry, device: starry)
require(dynamicWhitelistAddresses([ipv6Entry]).count == 1, "the node's IPv6 goes on the whitelist")

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

// No remote config: several Hosts share one jump, and only ProxyJump is written.
let jumpHosts = [
    SSHEffectiveHost(alias: "A", hostName: "192.0.2.1"),
    SSHEffectiveHost(alias: "B", hostName: "192.0.2.2"),
    SSHEffectiveHost(alias: "J", hostName: "192.0.2.3"),
    SSHEffectiveHost(alias: "K", hostName: "192.0.2.4", proxyJump: "A"),
]
let jumpBatch = try makeJumpOnlyMappings(aliases: ["B", "A", "B"], jump: "J", hosts: jumpHosts, existing: [])
require(jumpBatch.map(\.hostAlias) == ["A", "B"], "batch is sorted without duplicates")
require(jumpBatch.allSatisfy { $0.isJumpOnly && $0.proxyJump == "J" && $0.applied == nil && $0.deviceLabel == sshJumpOnlyLabel }, "batch shares the jump")
require(try makeJumpOnlyMappings(aliases: ["A"], jump: sshProxyJumpNone, hosts: jumpHosts, existing: []).first?.proxyJump == "none", "direct is allowed")
func jumpBatchRefused(_ aliases: [String], _ jump: String?, existing: [SSHMapping] = []) -> Bool {
    (try? makeJumpOnlyMappings(aliases: aliases, jump: jump, hosts: jumpHosts, existing: existing)) == nil
}
require(jumpBatchRefused([], "J"), "no hosts refused")
require(jumpBatchRefused(["A"], nil), "inherit writes nothing, so it is refused")
require(jumpBatchRefused(["A"], "a,b"), "unsafe jump refused")
require(jumpBatchRefused(["A", "a b"], "J"), "one unsafe alias refuses the whole batch")
require(jumpBatchRefused(["A", "B"], "B"), "jumping through a selected Host refused")
require(jumpBatchRefused(["A", "B"], "K"), "a cycle through the config refused")
require(jumpBatchRefused(["A", "B"], "J", existing: [mapping(lxz, "B", .lanIPv4)]), "a Host already configured refuses the batch")
require(!mapping(lxz, "x", .lanIPv4).isJumpOnly, "real devices are not jump-only")
require(!filterSSHMappings(jumpBatch, query: "无远程").isEmpty && filterSSHMappings(jumpBatch, query: "局域网").isEmpty, "searched by its label, not a hidden policy")

// The real ssh sees the jump while HostName and everything else stay from the main config.
let jumpOnlyBatch = try makeJumpOnlyMappings(aliases: ["LXZ-606", "WIN"], jump: "clawd", hosts: [], existing: [])
try writeDynamicSSHConfig(renderDynamicSSHConfig(jumpOnlyBatch), paths: paths)
let batchLXZ = try sshG(paths.config, host: "LXZ-606"), batchWIN = try sshG(paths.config, host: "WIN")
require(batchLXZ["proxyjump"] == "clawd" && batchLXZ["hostname"] == "192.0.2.1" && batchLXZ["user"] == "huawei" && batchLXZ["hostkeyalias"] == nil, "jump-only keeps the address")
require(batchWIN["proxyjump"] == "clawd" && batchWIN["hostname"] == "192.0.2.2" && batchWIN["port"] == "22", "both Hosts get the jump")
require(try sshG(paths.config, host: "clawd")["proxyjump"] == nil, "unselected Hosts stay untouched")
let directBatch = try makeJumpOnlyMappings(aliases: ["LXZ-606"], jump: sshProxyJumpNone, hosts: [], existing: [])
try writeDynamicSSHConfig(renderDynamicSSHConfig(directBatch), paths: paths)
require(try sshG(paths.config, host: "LXZ-606")["proxyjump"] == nil, "direct overrides the main config's jump")

// Groups: one row, one jump, changed together.
require(Set(jumpBatch.map(\.jumpGroup)).count == 1 && jumpBatch[0].jumpGroup != nil, "a batch is one group")
let otherBatch = try makeJumpOnlyMappings(aliases: ["K"], jump: sshProxyJumpNone, hosts: [], existing: jumpBatch)
require(otherBatch[0].jumpGroup != jumpBatch[0].jumpGroup, "each batch is its own group")
let realMapping = mapping(lxz, "Z", .lanIPv4)
let groupRows = sshMappingRows(jumpBatch + otherBatch + [realMapping])
require(groupRows.count == 3, "one row per group plus real devices")
guard case .group(let firstGroup) = groupRows[0], case .single(let single) = groupRows[2] else { fatalError("row kinds") }
require(firstGroup.aliases == ["A", "B"] && firstGroup.title == "A 等 2 个 Host" && firstGroup.proxyJump == "J", "group row")
require(single.hostAlias == "Z", "real device stays a single row")
let groupID = firstGroup.id

let rejumped = try updatingJumpGroup(jumpBatch + otherBatch + [realMapping], id: groupID, aliases: ["A", "B"], jump: "PYX", hosts: jumpHosts)
require(rejumped.filter { $0.jumpGroup == groupID }.allSatisfy { $0.proxyJump == "PYX" }, "changing the jump changes every member")
require(rejumped.first { $0.hostAlias == "K" }?.proxyJump == "none" && rejumped.first { $0.hostAlias == "Z" }?.keyID == "k2", "other rows untouched")
let reshaped = try updatingJumpGroup(jumpBatch, id: groupID, aliases: ["B", "C"], jump: "J", hosts: jumpHosts)
require(reshaped.map(\.hostAlias) == ["B", "C"] && reshaped.allSatisfy { $0.jumpGroup == groupID }, "members can be added and removed")
require((try? updatingJumpGroup(jumpBatch, id: groupID, aliases: ["A", "B"], jump: "B", hosts: jumpHosts)) == nil, "group cycle refused")
require((try? updatingJumpGroup(jumpBatch + [realMapping], id: groupID, aliases: ["A", "Z"], jump: "J", hosts: jumpHosts)) == nil, "a Host with a real device cannot join")
require((try? updatingJumpGroup(jumpBatch, id: groupID, aliases: [], jump: "J", hosts: jumpHosts)) == nil, "an empty group is refused")
try writeDynamicSSHConfig(renderDynamicSSHConfig(try updatingJumpGroup(
    try makeJumpOnlyMappings(aliases: ["LXZ-606", "WIN"], jump: "clawd", hosts: [], existing: [], group: groupID),
    id: groupID, aliases: ["LXZ-606", "WIN"], jump: sshProxyJumpNone, hosts: [])), paths: paths)
require(try sshG(paths.config, host: "LXZ-606")["proxyjump"] == nil && (try sshG(paths.config, host: "WIN"))["proxyjump"] == nil, "ssh sees the new jump on every member")

// Hosts saved one by one before groups existed are merged by jump, once.
var ungroupedA = SSHMapping(keyID: "", deviceLabel: sshJumpOnlyLabel, hostAlias: "a", policy: .lanIPv4, proxyJump: "2004")
var ungroupedB = ungroupedA; ungroupedB.id = UUID(); ungroupedB.hostAlias = "b"
var ungroupedC = ungroupedA; ungroupedC.id = UUID(); ungroupedC.hostAlias = "c"; ungroupedC.proxyJump = "other"
let mergedOld = mergeUngroupedJumpOnly([ungroupedA, ungroupedB, ungroupedC, realMapping])
require(mergedOld[0].jumpGroup == mergedOld[1].jumpGroup && mergedOld[0].jumpGroup != nil, "same jump merged")
require(mergedOld[2].jumpGroup != mergedOld[0].jumpGroup, "another jump stays apart")
require(mergedOld[3].jumpGroup == nil, "real devices never join a group")
require(mergeUngroupedJumpOnly(mergedOld) == mergedOld, "merging is stable")
require(renderDynamicSSHConfig(mergedOld) == renderDynamicSSHConfig([ungroupedA, ungroupedB, ungroupedC, realMapping]), "merging leaves the generated file unchanged")

// Dynamic addresses in the whitelist.
var wlIPv6 = mapping(win, "WIN", .publicIPv6); wlIPv6.applied = SSHTarget(hostName: "2001:DB8::1")
var wlIPv6Twin = mapping(lxz, "TWIN", .publicIPv6); wlIPv6Twin.applied = SSHTarget(hostName: "2001:db8:0::1")
var wlIPv4 = mapping(lxz, "LAN", .lanIPv4); wlIPv4.applied = SSHTarget(hostName: "10.0.0.1")
var wlEntry = mapping(win, "ENTRY", .tunnelEntry); wlEntry.applied = SSHTarget(hostName: "8.136.105.252", port: 20091)
let wlPending = mapping(win, "PENDING", .publicIPv6)
var wlJumpOnly = SSHMapping(keyID: "", deviceLabel: sshJumpOnlyLabel, hostAlias: "JUMP", policy: .lanIPv4, proxyJump: "x")
wlJumpOnly.applied = SSHTarget(hostName: "2001:db8::9")
let wanted = dynamicWhitelistAddresses([wlIPv6, wlIPv6Twin, wlIPv4, wlEntry, wlPending, wlJumpOnly])
require(wanted == ["2001:db8::1": ["TWIN", "WIN"]], "only applied IPv6 of real devices, canonical and shared")

let wlNow = Date(timeIntervalSince1970: 1000)
let manualEntry = WhitelistEntry(address: "2001:db8::2", name: "手动", sources: ["手动添加"])
let added = mergeDynamicWhitelist([manualEntry], wanted: wanted, excluded: [], now: wlNow)
require(added.added == ["2001:db8::1"] && added.entries.count == 2, "a new address is added")
let addedEntry = added.entries.first { $0.address == "2001:db8::1" }!
require(addedEntry.automaticSource == sshDynamicAutomaticSource && addedEntry.enabled && addedEntry.name.contains("TWIN、WIN"), "owned, enabled and named after its Hosts")
require(!addedEntry.isWeChatAutomatic, "the WeChat cleanup never touches it")
require(added.entries.first { $0.address == "2001:db8::2" } == manualEntry, "a manual entry is untouched")

let moved = mergeDynamicWhitelist(added.entries, wanted: ["2001:db8::3": ["WIN"]], excluded: [], now: wlNow)
require(moved.added == ["2001:db8::3"] && moved.removed == ["2001:db8::1"], "the old address goes when the Host moves")
require(moved.entries.contains(manualEntry), "moving keeps manual entries")
let emptied = mergeDynamicWhitelist(moved.entries, wanted: [:], excluded: [], now: wlNow)
require(emptied.entries == [manualEntry] && emptied.removed == ["2001:db8::3"], "removing the Host removes only what it owned")

let covered = mergeDynamicWhitelist([manualEntry], wanted: ["2001:db8::2": ["WIN"]], excluded: [], now: wlNow)
require(covered.entries == [manualEntry] && covered.added.isEmpty, "a manual entry already covers the address")
let keptManual = mergeDynamicWhitelist(covered.entries, wanted: [:], excluded: [], now: wlNow)
require(keptManual.entries == [manualEntry] && keptManual.removed.isEmpty, "and it stays when the Host moves away")

var disabledOwned = addedEntry; disabledOwned.enabled = false
require(mergeDynamicWhitelist([disabledOwned], wanted: wanted, excluded: [], now: wlNow).entries[0].enabled == false, "a disabled entry stays disabled")
let weChatOwned = WhitelistEntry(address: "2001:db8::1", name: "微信", sources: ["微信自动发现"], automaticSource: "wechat")
let takenOver = mergeDynamicWhitelist([weChatOwned], wanted: wanted, excluded: [], now: wlNow)
require(takenOver.entries[0].automaticSource == sshDynamicAutomaticSource && takenOver.added.isEmpty, "a WeChat entry is taken over so it cannot expire")

let refused = mergeDynamicWhitelist([], wanted: wanted, excluded: ["2001:db8::1"], now: wlNow)
require(refused.entries.isEmpty && refused.excluded == ["2001:db8::1"], "an address removed by hand stays out")
let fullList = (0..<256).map { WhitelistEntry(address: "2001:db8:1::\(String($0, radix: 16))", name: "n") }
let overflow = mergeDynamicWhitelist(fullList, wanted: wanted, excluded: [], now: wlNow)
require(overflow.entries.count == 256 && overflow.overCapacity == ["2001:db8::1"], "a full list refuses instead of evicting")
let stable = mergeDynamicWhitelist(added.entries, wanted: wanted, excluded: [], now: wlNow)
require(stable.added.isEmpty && stable.removed.isEmpty && stable.entries == added.entries, "nothing changes when nothing moved")

// A saved jump-only mapping round-trips.
let savedJumpOnly = try JSONDecoder().decode(SSHMapping.self, from: JSONEncoder().encode(jumpBatch[0]))
require(savedJumpOnly == jumpBatch[0] && savedJumpOnly.isJumpOnly, "jump-only survives saving")

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
