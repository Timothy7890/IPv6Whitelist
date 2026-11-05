import Foundation

struct WhitelistEntry: Codable, Identifiable, Equatable {
    var id: UUID = UUID()
    var address: String
    var name: String
    var enabled: Bool = true
    var sources: [String] = []
    var automaticSource: String?
    var firstSeen: Date?
    var lastSeen: Date?

    var isWeChatAutomatic: Bool { automaticSource == "wechat" }
}

struct RouteRecord: Codable, Equatable {
    var destination: String
    var gateway: String
    var flags: String
    var interface: String
}

struct ManagedRoute: Codable, Equatable {
    var address: String
    var gateway: String
}

struct HelperStatus: Codable {
    var enabled: Bool = false
    var wifiGateway: String? = nil
    var activeRoutes: [ManagedRoute] = []
    var conflicts: [String] = []
    var error: String? = nil
    var broadDefaults: [RouteRecord] = []
    var defaultIPv6Interface: String? = nil
    var updatedAt: Double = Date().timeIntervalSince1970
}

struct HelperRequest: Codable {
    var command: String
    var addresses: [String]? = nil
    var gateway: String? = nil
}

struct HelperResponse: Codable {
    var ok: Bool
    var message: String
    var status: HelperStatus? = nil
}

let helperProtocolVersion = 1
func helperSocketPath(uid: UInt32) -> String { "/var/run/wifi-ipv6-\(uid)/control.sock" }
