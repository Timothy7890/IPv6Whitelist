import Foundation
import Darwin

var checks = 0
func check(_ value: @autoclosure () -> Bool, _ message: String) {
    checks += 1
    if !value() { fatalError("FAIL: \(message)") }
}
let now = Date(timeIntervalSince1970: 1800000000)
func auto(_ address: String, age: TimeInterval = 0, enabled: Bool = true) -> WhitelistEntry {
    WhitelistEntry(address: address, name: "automatic", enabled: enabled, automaticSource: "wechat", firstSeen: now.addingTimeInterval(-age), lastSeen: now.addingTimeInterval(-age))
}
let sample = """
p12
cWeChat
f4
n[fd00::1]:456->[240e:ff:f100:5003::9]:80
TST=SYN_SENT
f5
n198.18.0.1:200->183.60.8.69:443
f6
n127.0.0.1:200->127.0.0.1:1082
f7
n[::]:444
TST=LISTEN
f8
n[::1]:200->[::1]:1082
f9
n[240e::1]:200->[::ffff:1.2.3.4]:80
f10
n[240e::1]:200->[fd00::2]:80
p99
n[240e::1]:200->[240e::bad]:80
"""
let scan = WeChatDiscovery.parse(sample, allowedPIDs: [12])
check(scan.addresses == ["240e:ff:f100:5003::9"], "SYN_SENT is learned; ignore listeners, fake/private/mapped and other PIDs")
check(scan.ipv4Connections == 1 && scan.proxyConnections == 2, "IPv4 and local-proxy counts")
for address in ["127.0.0.1", "::1", "::", "fe80::1", "ff02::1", "fc00::1", "5368:6164::1", "2001:db8::1", "2002:1234::1", "2001::1", "::ffff:8.8.8.8", "64:ff9b::808:808"] {
 check(WeChatDiscovery.publicAddress(address) == nil, "reject \(address)")
}
check(WeChatDiscovery.isWeChatPath("/Applications/WeChat.app/Contents/MacOS/WeChat"), "main process")
check(WeChatDiscovery.isWeChatPath("/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/MacOS/WeChatAppEx"), "helper process")
check(!WeChatDiscovery.isWeChatPath("/tmp/WeChat.app/Contents/MacOS/WeChat"), "untrusted install root")
check(!WeChatDiscovery.isWeChatPath("/Applications/WeChat.app/Contents/../Other"), "path escape")
let manual = WhitelistEntry(address: "240e::1", name: "manual", enabled: false)
let old = auto("240e::2", age: 8*86400)
let activeOld = auto("240e::3", age: 8*86400)
let disabled = auto("240e::4", age: 8*86400, enabled: false)
var merged = WeChatAddressPolicy.merge([manual, old, activeOld, disabled], observed: ["240e::1", "240e::3", "240e::4", "240e::5", "240e::6"], excluded: ["240e::6"], now: now)
check(merged.added == 1 && merged.removed == 1, "only stale disconnected auto evicted; exclusion respected")
check(merged.entries.first { $0.address == "240e::1" } == manual, "manual entry untouched")
check(merged.entries.first { $0.address == "240e::4" }?.enabled == false, "disabled stays disabled")
check(merged.entries.first { $0.address == "240e::3" }?.lastSeen == now, "active retained and timestamp refreshed")
let fullManual = (0..<256).map { WhitelistEntry(address: "240e::\(String($0 + 1, radix: 16))", name: "manual") }
merged = WeChatAddressPolicy.merge(fullManual, observed: ["240e:1::1"], excluded: [], now: now)
check(merged.entries == fullManual && merged.skipped == 1, "manual capacity never evicted")
let fullAuto = (0..<128).map { auto("240e::\(String($0+1, radix:16))", age: Double($0)) }
merged = WeChatAddressPolicy.merge(fullAuto, observed: ["240e:1::1", "240e::80"], excluded: [], now: now)
check(merged.entries.count == 128 && merged.added == 1 && merged.removed == 1, "automatic quota enforced")
check(merged.entries.contains { $0.address == "240e::80" }, "active oldest survives eviction")
check(!merged.entries.contains { $0.address == "240e::7f" }, "oldest inactive evicted")
let current = Set(fullAuto.map(\.address)).union(["240e:1::1"])
merged = WeChatAddressPolicy.merge(fullAuto, observed: current, excluded: [], now: now)
check(merged.skipped == 1 && merged.removed == 0, "no route churn when all 128 active")
let legacy = Data("[{\"id\":\"11111111-1111-1111-1111-111111111111\",\"address\":\"240e::1\",\"name\":\"legacy\",\"enabled\":true,\"sources\":[]}]".utf8)
let decoded = try JSONDecoder().decode([WhitelistEntry].self, from: legacy)
check(!decoded[0].isWeChatAutomatic, "legacy data migration")
let encoded = try JSONEncoder().encode([auto("240e::12")])
let roundTrip = try JSONDecoder().decode([WhitelistEntry].self, from: encoded)
check(roundTrip[0].lastSeen == now, "timestamps survive restart")
if CommandLine.arguments.contains("--live") {
 let live = try WeChatDiscovery.scan()
 print("LIVE processes=\(live.processCount) IPv6=\(live.addresses.sorted()) IPv4=\(live.ipv4Connections) local=\(live.proxyConnections)")
}
print("PASS: \(checks) checks")

if CommandLine.arguments.contains("--stress") {
    func descriptorCount() -> Int { (0..<4096).filter { fcntl(Int32($0), F_GETFD) >= 0 }.count }
    func threadCount() -> Int32 {
        var info = proc_taskinfo()
        let size = Int32(MemoryLayout.size(ofValue: info))
        precondition(proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &info, size) == size)
        return info.pti_threadnum
    }
    for _ in 0..<10 { _ = LocalCommand.run("/bin/echo", ["warmup"]) }
    let beforeFD = descriptorCount(), beforeThreads = threadCount()
    for i in 0..<1000 {
        let result = LocalCommand.run("/bin/echo", ["scan-\(i)"])
        check(result.code == 0 && result.output == "scan-\(i)\n", "repeated command \(i)")
    }
    for _ in 0..<20 {
        let started = ProcessInfo.processInfo.systemUptime
        let result = LocalCommand.run("/bin/sleep", ["5"], timeout: 0.02)
        check(result.code == -2 && ProcessInfo.processInfo.systemUptime - started < 1, "bounded timeout cleanup")
    }
    let input = String(repeating: "abcdef\n", count: 30000)
    let copied = LocalCommand.run("/bin/cat", [], input: input)
    check(copied.code == 0 && copied.output == input, "large stdin/output cannot deadlock")
    let tooMuch = BoundedCommandRunner.run("/bin/cat", [], input: input, outputLimit: 1000)
    check(tooMuch.code == -2, "output cap")
    let failed = LocalCommand.run("/no/such/ipv6-command", [])
    check(failed.code == -1, "spawn failure cleanup")
    let exitCode = LocalCommand.run("/bin/sh", ["-c", "printf error >&2; exit 7"])
    check(exitCode.code == 7 && exitCode.output == "error", "stderr and nonzero exit")
    let grandchild = LocalCommand.run("/bin/sh", ["-c", "sleep 5 & exit 0"], timeout: 0.05)
    check(grandchild.code == -2, "descendant pipe cannot hold scanner forever")
    let afterFD = descriptorCount(), afterThreads = threadCount()
    check(afterFD <= beforeFD + 1, "no descriptor growth")
    check(afterThreads <= beforeThreads + 1, "no waiting-thread growth")
    print("STRESS PASS: 1000 commands + 20 timeouts; fds \(beforeFD)->\(afterFD); threads \(beforeThreads)->\(afterThreads); total checks \(checks)")
}
