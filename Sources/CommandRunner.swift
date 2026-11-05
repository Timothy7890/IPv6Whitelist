import Foundation
import Darwin

// All child lifetime and I/O are owned by the calling background worker.
// No Foundation Process termination callbacks or GCD waiter/reader jobs remain
// after a command returns. Descriptors close on every error/timeout path.
struct ExecutedCommand {
    var code: Int32
    var output: String
}

enum BoundedCommandRunner {
    static func run(_ executable: String, _ arguments: [String], input: String? = nil,
                    timeout: TimeInterval = 10, outputLimit: Int = 4_194_304) -> ExecutedCommand {
        guard timeout > 0, outputLimit > 0 else { return ExecutedCommand(code: -1, output: "无效命令限制") }
        var pipeFDs: [Int32] = [-1, -1]
        guard pipe(&pipeFDs) == 0 else { return failure("创建输出管道失败") }
        defer { if pipeFDs[0] >= 0 { close(pipeFDs[0]) }; if pipeFDs[1] >= 0 { close(pipeFDs[1]) } }
        for fd in pipeFDs { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }
        let inputFD: Int32
        if let input {
            guard input.utf8.count <= 1_048_576 else { return ExecutedCommand(code: -1, output: "命令输入过大") }
            var template = Array((NSTemporaryDirectory() + "ipv6-command-XXXXXX").utf8CString)
            inputFD = mkstemp(&template)
            guard inputFD >= 0 else { return failure("创建命令输入失败") }
            // Unlink immediately: the child receives an fd, never a pathname.
            _ = unlink(template)
            let bytes = Array(input.utf8)
            let written = bytes.withUnsafeBytes { data -> Bool in
                var offset = 0
                while offset < data.count {
                    let n = Darwin.write(inputFD, data.baseAddress!.advanced(by: offset), data.count - offset)
                    if n < 0 && errno == EINTR { continue }
                    guard n > 0 else { return false }
                    offset += n
                }
                return true
            }
            guard written, lseek(inputFD, 0, SEEK_SET) >= 0 else {
                close(inputFD); return failure("写入命令输入失败")
            }
        } else {
            inputFD = open("/dev/null", O_RDONLY | O_CLOEXEC)
            guard inputFD >= 0 else { return failure("打开命令输入失败") }
        }
        defer { close(inputFD) }
        _ = fcntl(inputFD, F_SETFD, FD_CLOEXEC)
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { return failure("初始化子进程失败") }
        defer { posix_spawn_file_actions_destroy(&actions) }
        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else { return failure("初始化子进程属性失败") }
        defer { posix_spawnattr_destroy(&attributes) }
        let codes = [posix_spawn_file_actions_adddup2(&actions, inputFD, STDIN_FILENO),
                     posix_spawn_file_actions_adddup2(&actions, pipeFDs[1], STDOUT_FILENO),
                     posix_spawn_file_actions_adddup2(&actions, pipeFDs[1], STDERR_FILENO),
                     posix_spawnattr_setpgroup(&attributes, 0),
                     posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT))]
        guard codes.allSatisfy({ $0 == 0 }) else { return ExecutedCommand(code: -1, output: "配置子进程失败") }
        let environment = ProcessInfo.processInfo.environment.merging(["LC_ALL": "C"]) { _, new in new }
        var argv = ([executable] + arguments).map { strdup($0) } + [nil]
        var envp = environment.sorted(by: { $0.key < $1.key }).map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { argv.compactMap { $0 }.forEach { free($0) }; envp.compactMap { $0 }.forEach { free($0) } }
        var pid: pid_t = 0
        let spawned = posix_spawn(&pid, executable, &actions, &attributes, &argv, &envp)
        guard spawned == 0 else { return ExecutedCommand(code: -1, output: "无法启动命令：\(String(cString: strerror(spawned)))") }
        close(pipeFDs[1]); pipeFDs[1] = -1
        let fd = pipeFDs[0]
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var output = Data()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        var status: Int32 = 0
        var reaped = false
        var eof = false
        var problem: String?
        while !(reaped && eof) {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n > 0 {
                if output.count + n > outputLimit { problem = "命令输出超过限制"; break }
                output.append(contentsOf: buffer.prefix(n))
            } else if n == 0 { eof = true }
            else if errno != EAGAIN && errno != EINTR { problem = "读取命令输出失败"; break }
            if !reaped {
                let result = waitpid(pid, &status, WNOHANG)
                if result == pid { reaped = true }
                else if result < 0 && errno != EINTR { problem = "读取子进程状态失败"; break }
            }
            if reaped && eof { break }
            if ProcessInfo.processInfo.systemUptime >= deadline { problem = "操作超时"; break }
            if n <= 0 {
                if eof { usleep(5_000) }
                else {
                    var event = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                    _ = poll(&event, 1, 20)
                }
            }
        }
        if let problem {
            // Include descendants retaining our output pipe. The group is unique
            // to this invocation; no user app or other invocation is signalled.
            _ = kill(-pid, SIGKILL)
            if !reaped {
                while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
            }
            return ExecutedCommand(code: -2, output: problem)
        }
        let code: Int32 = status & 0x7f == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
        return ExecutedCommand(code: code, output: String(decoding: output, as: UTF8.self))
    }

    private static func failure(_ message: String) -> ExecutedCommand {
        ExecutedCommand(code: -1, output: "\(message)：\(String(cString: strerror(errno)))")
    }
}
