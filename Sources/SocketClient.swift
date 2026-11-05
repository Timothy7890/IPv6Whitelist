import Foundation
import Darwin

enum LocalServiceError: LocalizedError {
    case unavailable(String)
    var errorDescription: String? {
        switch self { case .unavailable(let reason): return reason }
    }
}

enum SocketClient {
    static func request(_ request: HelperRequest, timeout: Int = 5) throws -> HelperResponse {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw LocalServiceError.unavailable("无法创建本地通信连接") }
        defer { close(fd) }
        var noSignal: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout.size(ofValue: noSignal)))
        var duration = timeval(tv_sec: timeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &duration, socklen_t(MemoryLayout.size(ofValue: duration)))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &duration, socklen_t(MemoryLayout.size(ofValue: duration)))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let path = helperSocketPath(uid: getuid())
        let pathBytes = Array(path.utf8CString)
        guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw LocalServiceError.unavailable("本地通信地址过长")
        }
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { destination in
                pathBytes.withUnsafeBufferPointer { source in
                    destination.update(from: source.baseAddress!, count: source.count)
                }
            }
        }
        let originalFlags = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, originalFlags | O_NONBLOCK)
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connected != 0 {
            guard errno == EINPROGRESS || errno == EAGAIN else { throw LocalServiceError.unavailable("路由服务尚未启动") }
            var event = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            guard poll(&event, 1, Int32(timeout * 1000)) > 0 else {
                throw LocalServiceError.unavailable("连接路由服务超时，请重新启动管理服务")
            }
            var socketError: Int32 = 0
            var errorSize = socklen_t(MemoryLayout.size(ofValue: socketError))
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorSize) == 0, socketError == 0 else {
                throw LocalServiceError.unavailable("无法连接路由服务")
            }
        }
        _ = fcntl(fd, F_SETFL, originalFlags)
        var peerUID: uid_t = 99999
        var peerGID: gid_t = 99999
        guard getpeereid(fd, &peerUID, &peerGID) == 0, peerUID == 0 else {
            throw LocalServiceError.unavailable("拒绝连接：路由服务不是管理员进程")
        }
        var payload = try JSONEncoder().encode(request)
        payload.append(0x0a)
        try payload.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let sent = send(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, 0)
                if sent < 0 && errno == EINTR { continue }
                guard sent > 0 else { throw LocalServiceError.unavailable("发送路由请求失败") }
                offset += sent
            }
        }
        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while response.count <= 1_048_576 {
            let count = recv(fd, &buffer, buffer.count, 0)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw LocalServiceError.unavailable("路由服务未及时响应") }
            response.append(contentsOf: buffer.prefix(count))
            if let newline = response.firstIndex(of: 0x0a) {
                return try JSONDecoder().decode(HelperResponse.self, from: response.prefix(upTo: newline))
            }
        }
        throw LocalServiceError.unavailable("路由服务响应超出大小限制")
    }
}

actor RouteService {
    func request(_ message: HelperRequest) throws -> HelperResponse {
        try SocketClient.request(message, timeout: message.command == "status" ? 5 : 60)
    }
}

typealias CommandResult = ExecutedCommand

enum LocalCommand {
    static func run(_ executable: String, _ arguments: [String], input: String? = nil, timeout: TimeInterval = 10) -> CommandResult {
        BoundedCommandRunner.run(executable, arguments, input: input, timeout: timeout)
    }
}

func shellQuote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }
func appleScriptString(_ text: String) -> String {
    "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\n", with: "\\n") + "\""
}
