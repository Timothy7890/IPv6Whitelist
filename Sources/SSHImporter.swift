import Foundation
import Darwin

struct SSHEffectiveHost: Identifiable, Equatable {
    var alias: String
    var hostName: String
    var port: Int?
    var id: String { alias }
    var display: String {
        guard let port else { return hostName }
        return hostName.contains(":") ? "[\(hostName)]:\(port)" : "\(hostName):\(port)"
    }
}

struct SSHImportResult {
    var entries: [WhitelistEntry]
    var warnings: [String]
}

/// Deliberately never invokes ssh, a shell, Match exec, ProxyCommand, or DNS.
/// Reads only Host, HostName, Include and a safe subset of Match conditions.
enum SSHImporter {
    static func load(configPath: String = NSHomeDirectory() + "/.ssh/config") -> SSHImportResult {
        let reader = Reader()
        let path = NSString(string: configPath).expandingTildeInPath
        let nodes = reader.read(path, stack: [])
        var grouped: [String: WhitelistEntry] = [:]
        for alias in reader.aliases.sorted(by: { $0.localizedStandardCompare($1) == .orderedAscending }) {
            var state = Evaluation(alias: alias)
            reader.evaluate(nodes, state: &state)
            let hostname = state.hostname ?? alias
            guard let address = canonicalIPv6(hostname) else {
                if hostname.contains(":") {
                    reader.warn("\(alias)：IPv6 地址不适合通过 Wi-Fi 网关直连，已跳过。")
                }
                continue
            }
            let source = state.hostnameSource ?? reader.aliasSources[alias] ?? "SSH 配置"
            if var entry = grouped[address] {
                entry.name += "、" + alias
                if !entry.sources.contains(source) { entry.sources.append(source) }
                grouped[address] = entry
            } else {
                grouped[address] = WhitelistEntry(address: address, name: alias, sources: [source])
            }
        }
        return SSHImportResult(entries: grouped.values.sorted {
            $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }, warnings: reader.warnings)
    }

    /// Every concrete Host alias with the values ssh would use for it.
    static func effectiveHosts(configPath: String = NSHomeDirectory() + "/.ssh/config") -> [SSHEffectiveHost] {
        let reader = Reader()
        let nodes = reader.read(NSString(string: configPath).expandingTildeInPath, stack: [])
        return reader.aliases.sorted { $0.localizedStandardCompare($1) == .orderedAscending }.map { alias in
            var state = Evaluation(alias: alias)
            reader.evaluate(nodes, state: &state)
            return SSHEffectiveHost(alias: alias, hostName: state.hostname ?? alias, port: state.port)
        }
    }

    private indirect enum Node {
        case directive(String, [String], String)
        case include([Node])
    }

    private struct Evaluation {
        let alias: String
        var active = true
        var hostname: String?
        var hostnameSource: String?
        var port: Int?
    }

    private final class Reader {
        var aliases: Set<String> = []
        var aliasSources: [String: String] = [:]
        var warnings: [String] = []
        private var warningSet: Set<String> = []
        private var fileCount = 0
        private var totalBytes = 0
        private let maxFileBytes = 2 * 1024 * 1024
        private let maxTotalBytes = 8 * 1024 * 1024

        func warn(_ text: String) {
            if warningSet.insert(text).inserted, warnings.count < 80 { warnings.append(text) }
        }

        func read(_ rawPath: String, stack: [String]) -> [Node] {
            let url = URL(fileURLWithPath: rawPath).standardizedFileURL.resolvingSymlinksInPath()
            let path = url.path
            guard stack.count < 12, fileCount < 128, !stack.contains(path) else {
                warn("Include 存在循环或超过安全读取上限，部分配置未导入。")
                return []
            }
            do {
                let properties = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                guard properties.isRegularFile == true, let fileSize = properties.fileSize,
                      fileSize <= maxFileBytes, totalBytes + fileSize <= maxTotalBytes else {
                    warn("\(display(path))：不是普通文件或超过安全读取上限。")
                    return []
                }
                let handle = try FileHandle(forReadingFrom: url)
                defer { try? handle.close() }
                let data = try handle.read(upToCount: maxFileBytes + 1) ?? Data()
                guard data.count <= maxFileBytes, totalBytes + data.count <= maxTotalBytes,
                      let content = String(data: data, encoding: .utf8) else {
                    warn("\(display(path))：无法按 UTF-8 安全读取。")
                    return []
                }
                fileCount += 1
                totalBytes += data.count
                var nodes: [Node] = []
                for (offset, line) in content.components(separatedBy: .newlines).enumerated() {
                    let location = "\(display(path)):\(offset + 1)"
                    guard line.utf8.count < 32768 else {
                        warn("\(location)：该行过长，已跳过。")
                        continue
                    }
                    guard let (keyword, arguments) = tokenize(line) else {
                        if !line.trimmingCharacters(in: .whitespaces).hasPrefix("#"), !line.trimmingCharacters(in: .whitespaces).isEmpty {
                            warn("\(location)：无法解析该行，已跳过。")
                        }
                        continue
                    }
                    switch keyword {
                    case "include":
                        var children: [Node] = []
                        for pattern in arguments {
                            for included in expand(pattern, source: location) {
                                children += read(included, stack: stack + [path])
                            }
                        }
                        nodes.append(.include(children))
                    case "host":
                        for alias in arguments where !alias.contains("*") && !alias.contains("?") && !alias.hasPrefix("!") {
                            guard aliases.count < 4096 else {
                                warn("Host 别名超过安全读取上限，部分配置未导入。")
                                break
                            }
                            aliases.insert(alias)
                            if aliasSources[alias] == nil { aliasSources[alias] = location }
                        }
                        nodes.append(.directive(keyword, arguments, location))
                    case "hostname", "match", "port":
                        nodes.append(.directive(keyword, arguments, location))
                    default:
                        break
                    }
                }
                return nodes
            } catch {
                warn("\(display(path))：无法读取 SSH 配置。")
                return []
            }
        }

        func evaluate(_ nodes: [Node], state: inout Evaluation) {
            for node in nodes {
                switch node {
                case .include(let children):
                    if state.active {
                        // Host lines in an included file do not apply after it ends.
                        evaluate(children, state: &state)
                        state.active = true
                    }
                case .directive(let keyword, let args, let source):
                    switch keyword {
                    case "host": state.active = matches(args, value: state.alias)
                    case "hostname":
                        if state.active, state.hostname == nil, let first = args.first {
                            state.hostname = first.replacingOccurrences(of: "%h", with: state.alias)
                            state.hostnameSource = source
                        }
                    case "port":
                        if state.active, state.port == nil, let first = args.first { state.port = Int(first) }
                    case "match":
                        state.active = matchCondition(args, state: state, source: source)
                    default: break
                    }
                }
            }
        }

        private func matchCondition(_ args: [String], state: Evaluation, source: String) -> Bool {
            if args.map({ $0.lowercased() }) == ["all"] { return true }
            var result = true
            var index = 0
            while index < args.count {
                let condition = args[index].lowercased()
                let negated = condition.hasPrefix("!")
                let key = negated ? String(condition.dropFirst()) : condition
                guard (key == "host" || key == "originalhost"), index + 1 < args.count else {
                    warn("\(source)：跳过不支持的 Match 条件块（不会执行 exec）；导入结果请核对。")
                    return false
                }
                let value = key == "originalhost" ? state.alias : (state.hostname ?? state.alias)
                let matched = matches(args[index + 1].components(separatedBy: ","), value: value)
                result = result && (negated ? !matched : matched)
                index += 2
            }
            return !args.isEmpty && result
        }

        private func matches(_ patterns: [String], value: String) -> Bool {
            var positive = false
            for raw in patterns {
                let negated = raw.hasPrefix("!")
                let pattern = negated ? String(raw.dropFirst()) : raw
                let matched = pattern.lowercased().withCString { p in
                    value.lowercased().withCString { v in fnmatch(p, v, 0) == 0 }
                }
                if matched && negated { return false }
                if matched { positive = true }
            }
            return positive
        }

        private func expand(_ pattern: String, source: String) -> [String] {
            guard !pattern.contains("%"), !pattern.contains("${"), !pattern.contains("\0") else {
                warn("\(source)：跳过含动态变量的 Include 路径。")
                return []
            }
            let expanded = NSString(string: pattern).expandingTildeInPath
            let path = expanded.hasPrefix("/") ? expanded : NSHomeDirectory() + "/.ssh/" + expanded
            var result = glob_t()
            let code = path.withCString { glob($0, 0, nil, &result) }
            defer { globfree(&result) }
            if code == GLOB_NOMATCH { return [] }
            guard code == 0, let paths = result.gl_pathv else {
                warn("\(source)：无法展开 Include 路径。")
                return []
            }
            let count = min(Int(result.gl_pathc), 128)
            if Int(result.gl_pathc) > 128 { warn("\(source)：Include 匹配文件过多，仅读取前 128 个。") }
            return (0..<count).compactMap { paths[$0].map { String(cString: $0) } }
        }

        private func display(_ path: String) -> String {
            let home = NSHomeDirectory()
            return path.hasPrefix(home + "/") ? "~" + String(path.dropFirst(home.count)) : path
        }

        private func tokenize(_ line: String) -> (String, [String])? {
            let chars = Array(line)
            var index = 0
            while index < chars.count, chars[index].isWhitespace { index += 1 }
            guard index < chars.count, chars[index] != "#" else { return nil }
            var keyword = ""
            while index < chars.count, !chars[index].isWhitespace, chars[index] != "=" {
                keyword.append(chars[index]); index += 1
            }
            while index < chars.count, chars[index].isWhitespace { index += 1 }
            if index < chars.count, chars[index] == "=" { index += 1 }
            var tokens: [String] = []
            var token = ""
            var quote: Character?
            var started = false
            while index < chars.count {
                let char = chars[index]
                if char == "\\", index + 1 < chars.count {
                    index += 1; token.append(chars[index]); started = true
                } else if let currentQuote = quote {
                    if char == currentQuote { quote = nil } else { token.append(char) }
                    started = true
                } else if char == "\"" || char == "'" {
                    quote = char; started = true
                } else if char == "#" {
                    break
                } else if char.isWhitespace {
                    if started { tokens.append(token); token = ""; started = false }
                } else {
                    token.append(char); started = true
                }
                index += 1
            }
            guard quote == nil, !keyword.isEmpty else { return nil }
            if started { tokens.append(token) }
            return (keyword.lowercased(), tokens)
        }
    }
}
