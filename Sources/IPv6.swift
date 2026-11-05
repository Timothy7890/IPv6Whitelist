import Foundation
import Darwin

/// A single routable IPv6 host only; no interface zone, subnet, DNS name or IPv4 tunnel literal.
func canonicalIPv6(_ input: String) -> String? {
    var value = input.trimmingCharacters(in: .whitespacesAndNewlines)
    if value.hasSuffix("/128") { value.removeLast(4) }
    if value.hasPrefix("[") && value.hasSuffix("]") {
        value.removeFirst()
        value.removeLast()
    }
    guard !value.isEmpty, !value.contains("%"), !value.contains("/"),
          !value.contains("\0") else { return nil }
    var parsed = in6_addr()
    guard value.withCString({ inet_pton(AF_INET6, $0, &parsed) }) == 1 else { return nil }
    let bytes = withUnsafeBytes(of: parsed) { Array($0) }
    // ::/96 includes unspecified, loopback and legacy IPv4-compatible addresses.
    guard !bytes.prefix(12).allSatisfy({ $0 == 0 }),
          !(bytes.prefix(10).allSatisfy({ $0 == 0 }) && bytes[10] == 255 && bytes[11] == 255),
          bytes[0] != 255,
          // Link-local hosts require a zone and already have on-link routes; do not install gateway routes for them.
          !(bytes[0] == 254 && (bytes[1] & 0xc0) == 0x80) else { return nil }
    var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    guard inet_ntop(AF_INET6, &parsed, &output, socklen_t(output.count)) != nil else { return nil }
    return String(cString: output)
}

let ipv6ValidationExplanation = "请输入单个 IPv6 地址（可带方括号或 /128）。不接受域名、其他网段、带 % 接口的地址、链路本地地址、未指定地址、回环、多播或 IPv4 映射/兼容地址。"
