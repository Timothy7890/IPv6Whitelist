import Foundation

func require(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() { fatalError(message) }
}

if CommandLine.arguments.contains("--seed") {
    let result = SSHImporter.load()
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(result.entries).write(to: URL(fileURLWithPath: "work/WiFiIPv6/initial-whitelist.json"))
    for entry in result.entries { print("\(entry.name): \(entry.address)") }
    print("Imported \(result.entries.count) unique IPv6 addresses; warnings: \(result.warnings.count)")
    result.warnings.forEach { print($0) }
} else {
    require(canonicalIPv6(" [2001:DB8:0::1]/128 \n") == "2001:db8::1", "canonicalization")
    require(canonicalIPv6("fd00::1234") == "fd00::1234", "ULA accepted")
    for invalid in ["", "::", "::1", "::2", "::ffff:192.0.2.1", "::192.0.2.1", "ff02::1", "fe80::1", "fe80::1%en0", "2001:db8::/64", "2001:db8::1;touch /tmp/x", "[2001:db8::1]:22", "example.com"] {
        require(canonicalIPv6(invalid) == nil, "invalid accepted: \(invalid)")
    }
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("wifi-ipv6-import-tests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let included = directory.appendingPathComponent("included config.conf")
    try """
    Host included alias2
      HostName [2001:DB8::20] # duplicate aliases
    Host dup
      HostName 2001:db8:0:0::20
    """.write(to: included, atomically: true, encoding: .utf8)
    let config = directory.appendingPathComponent("config")
    let marker = directory.appendingPathComponent("SHOULD_NOT_EXIST").path
    try """
    # HostName 2001:db8::dead
    Include "\(directory.path)/*.conf"
    Host first
      HostName = "2001:DB8::10"
      HostName 2001:db8::11
    Host app*
      HostName 2001:db8::30
    Host appOne
    Host blocked
    Host !blocked *
      HostName 2001:db8::40
    Host matched
    Match originalhost matched
      HostName 2001:db8::50
    Match exec "touch \(marker)"
      HostName 2001:db8::bad
    Host unsafe
      ProxyCommand touch \(marker)
      HostName 2001:db8::60
    """.write(to: config, atomically: true, encoding: .utf8)
    let result = SSHImporter.load(configPath: config.path)
    let byAddress = Dictionary(uniqueKeysWithValues: result.entries.map { ($0.address, $0) })
    require(byAddress["2001:db8::20"]?.name == "alias2、dup、included", "include/dedup/grouped names")
    require(byAddress["2001:db8::10"]?.name == "first", "first value wins")
    require(byAddress["2001:db8::30"]?.name == "appOne", "wildcard inheritance")
    require(byAddress["2001:db8::40"]?.name.contains("matched") == true, "first earlier wildcard wins over Match")
    require(byAddress["2001:db8::bad"] == nil, "unsafe Match ignored")
    require(result.warnings.contains(where: { $0.contains("Match") }), "unsafe Match warning")
    require(!FileManager.default.fileExists(atPath: marker), "must never execute SSH scripts")
    try "Include \(config.path)\nHost cycle\n HostName fd00::1234\n".write(to: config, atomically: true, encoding: .utf8)
    let cycle = SSHImporter.load(configPath: config.path)
    require(cycle.warnings.contains(where: { $0.contains("循环") }), "cycle warning")
    require(cycle.entries.first?.address == "fd00::1234", "read continuing after cycle")
    print("PASS IPv6 validation, literal/quotes/comments, include globs, dedup, first-value, wildcard negation, safe Match, no execution, include cycles")
}
