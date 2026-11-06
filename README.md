# IPv6 白名单

本机使用的 macOS 原生工具：为白名单中的 IPv6 地址维护经 Wi-Fi `en0` 出口的 `/128` 主机路由，让 SSH 等直连应用无需指定 `-b`。当前版本面向 **Apple Silicon、macOS 15 或更新版本**。

## 开始使用

1. 手动打开 **IPv6 白名单.app**。初始白名单已经从本机 SSH 配置导入 **11 个不同 IPv6 地址，覆盖 15 个 SSH 别名**；重复地址合并显示。
2. 检查列表中的勾选项，点击 **开启管理**，完成 macOS 管理员授权。辅助程序未运行时，需要授权安装并启动它；仅打开窗口不会启用路由。
3. 正常使用 `ssh 3090C` 等命令。每个已勾选地址对应一条独立主机路由，最多支持 256 个地址。

可以添加地址、双击编辑、取消勾选或移除条目；开启管理后会同步更新路由。**导入 SSH** 可重复执行，将新地址加入列表并合并已有来源，不删除之前导入或手动添加的地址。只导入配置中的 IPv6 字面地址，不解析域名。

管理服务约每 3 秒读取 `en0` 当前的 IPv6 网关及可用本机地址。切换 Wi-Fi、网络前缀或本机地址变化时，重新维护本应用创建的主机路由；新网络没有 IPv6 时清理旧路由并等待。网关及本机源地址均不写死。

**关闭窗口后仍在菜单栏运行。** 点击“停止管理”会清理本应用管理的路由；退出应用会请求清理并停止辅助程序。应用异常退出时，辅助程序在约 90 秒没有心跳后尝试清理退出；系统命令失败会影响清理结果。当前没有登录自启或常驻 LaunchDaemon。

## 与 Shadowrocket 配合

本应用负责指定目标的系统路由，不配置 Shadowrocket，也不保证白名单以外的流量已经通过代理。

- 如果之前添加过经 Wi-Fi 的宽泛 IPv6 默认路由，其他 IPv6 仍可能直连。界面会提示；需要点击 **移除默认直连** 并明确确认，才尝试删除检测到的那条静态、非接口限定默认路由。不会自动删除 Wi-Fi 原生的接口路由。
- **其余公网 IPv6 的接管、代理规则和节点 IPv6 支持需要另行配置并验证。** 删除默认直连路由后，若 Shadowrocket 没有接管，白名单外 IPv6 可能不可用。
- 使用系统 HTTP/HTTPS 代理的应用会先连接本地代理。还需要在 Shadowrocket 中给白名单设置 `DIRECT` 规则，才能表达相同的分流意图。使用应用中的“复制直连规则”，放到当前配置 `[Rule]` 区段中其他可能命中的规则之前。
- 白名单直连服务器能够看到当前网络的真实公网 IPv6。界面的公网出口是路由抽样；即使接口显示 `utun`，也不能据此断言流量已经过代理节点。实际出口需要另外验证。

既有同目标主机路由不会被覆盖或自动接管，界面会显示冲突。本应用只管理自己成功创建并持续核对的路由。

## 本地文件与权限

白名单保存于：

```text
~/Library/Application Support/IPv6Whitelist/whitelist.json
```

可通过界面打开数据目录。文件采用原子写入，权限为 `0600`；目录创建权限为 `0700`。无法解析已有数据时保留原文件并停止覆盖保存。初始种子仅在没有用户数据文件时使用。

管理员授权安装的辅助程序路径：

```text
/Library/PrivilegedHelperTools/local.timo.ipv6-whitelist-helper
```

辅助程序通过 root 所有的运行目录和受限 UNIX socket 通信，校验连接用户；只接受固定操作及经过校验的单个 IPv6 地址，不接受任意 shell 命令、路径或其他网卡。客户端也核对服务端为 root。辅助程序退出后可执行文件保留，但不会自动运行。

SSH 导入只读取 `~/.ssh/config` 及其 `Include` 配置，不读取 `IdentityFile` 指向的密钥或密码，不修改 SSH 文件，不运行 `ssh -G`、`Match exec` 或 `ProxyCommand`，也不发起网络连接。支持 Include/glob、Host 通配符与首值优先；不支持的 Match 条件会跳过并在运行记录中提示。应用无遥测。除下面可选的“SSH Config 更新”外，不连接远程服务。

## 编译与验证

需要 Apple Command Line Tools/Xcode 提供的 Swift 编译器。在本项目目录运行：

```bash
bash ./build.sh "$PWD/build"
open "$PWD/build/IPv6 白名单.app"
```

`build.sh` 的第一个参数是输出目录；省略时使用项目内的 `build`。脚本编译 arm64/macOS 15 目标并进行本机 ad-hoc 签名，不需要第三方包。该签名不等同于 Developer ID 公证。

以下测试不修改系统路由：

```bash
"./build/IPv6 白名单.app/Contents/MacOS/ipv6-route-helper" --self-test
xcrun swiftc Sources/Models.swift Sources/IPv6.swift Sources/SSHImporter.swift \
  ImporterTests/main.swift -o ./build/import-tests
./build/import-tests
```

辅助程序自测覆盖路由解析、归属核对、Wi-Fi 变化、参数限制与 socket 协议；导入自测覆盖地址校验、注释引号、Include、重复地址、通配符、条件块与禁止脚本执行。

`integration-test.py` 是供维护者使用的管理员集成测试：会临时添加两条文档保留地址的 `/128` 路由，检查增删、普通选路、退出清理及默认路由保持不变，最终清理测试数据。它不发送外部网络数据；运行前需了解会实际修改测试路由，且当前 Wi-Fi 必须有 IPv6 网关。

主要源码分工：`AppModel.swift` 管理状态与持久化；`HelperMain.swift` 管理权限边界和路由生命周期；`SocketClient.swift` 负责本地通信；`SSHImporter.swift` 与 `IPv6.swift` 负责配置导入和地址校验；`Views.swift`/`AppEntry.swift` 提供窗口与菜单栏。

## 1.2.0：SSH Config 更新

新工作空间“SSH Config 更新”根据 netbridge 上报的地址，一键更新指定 SSH Host 的 `HostName`。默认不工作，需要设置令牌并启用；只在打开页面、点击刷新或一键更新时读取 Controller，没有后台定时任务。

1. 在 Controller 配置 `NETBRIDGE_CONTROLLER_READ_ONLY_TOKEN`，把令牌粘贴到 App，保存在 macOS 钥匙串。这个令牌只能调用 `GET /v1/tunnels`。
2. 点击“启用”：先备份 `~/.ssh/config` 为同目录的 `config.netbridge-backup-时间`，再在最顶部加入 `Include ~/.ssh/config.d/netbridge-dynamic`。其余内容按字节保留；如果 Include 已存在但位置不对，只提示手动调整。
3. 添加 Host：选择 B 端设备、SSH Host 和地址类型（局域网 IPv4、公网 IPv6 或 netbridge 公网入口）。一台设备可以对应多个 Host。
4. 点击“一键更新”。之后 App 只写生成的 `~/.ssh/config.d/netbridge-dynamic`。

SSH 对同一选项采用最先读到的值，所以生成的文件优先于主配置；主配置里其他选项（`User`、`ProxyJump`、密钥等）继续生效。移除映射后，该 Host 恢复使用主配置的值；删除 Include 那一行即可全部恢复。

- 读取 Controller 时可以选择或填写 SOCKS5 代理（如 `127.0.0.1:1085`），留空则直连。常用代理的名称和端口在 `Sources/NetbridgeSync.swift` 的 `socksProxyPresets`。只影响这一个请求，不改变系统或 SSH 的网络；令牌仍由 HTTPS 加密。
- 每个 Host 可以单独配置跳板：沿用主配置（默认，不写入）、直连（写入 `ProxyJump none`）或搜索选择一个 Host。修改后立即写入生成的文件，不需要一键更新；会形成循环的选择会被拒绝。
- Host 和跳板列表都可以用键盘选择：在搜索框里按 ↑↓ 移动高亮，回车确认，打字可继续筛选。没有高亮时，回车只在结果唯一时才选中。
- 映射保存在 `ssh-config-sync.json`（0600）。设备离线或没有对应地址时保留上次的值，不会删除。
- 设备按公钥 `key_id` 绑定，名称重复也不会串。
- 生成的配置带 `HostKeyAlias netbridge-<Host>`，指纹按 Host 而不是 IP 记录：IP 变化不会要求重新信任，但主机密钥仍会校验；每个 Host 启用后第一次连接会询问一次。
- 写入前校验 Host 名和地址，拒绝可能注入 SSH 选项的内容。令牌只发送到配置的 HTTPS 地址，并拒绝重定向。
- App 不读取 SSH 密钥，也不发起 SSH 连接。重新编译后签名会变，读取钥匙串时 macOS 可能再次询问。
- 公网 IPv6 变化后不会自动更新 IPv6 白名单，需要重新“导入 SSH”；旧地址要手动移除。

开发验证：

```bash
xcrun swiftc -swift-version 5 Sources/Models.swift Sources/IPv6.swift Sources/SSHImporter.swift \
  Sources/NetbridgeSync.swift SSHSyncTests/main.swift -o /tmp/ssh-sync-tests
/tmp/ssh-sync-tests
```

## 1.1.0：自动维护微信 IPv6

主窗口新增“自动维护微信 IPv6”开关。首次使用默认关闭；启用后会记住设置，但应用仍需手动启动并开启路由管理。已手动添加的微信条目仍是手动条目，不会自动清理。

- 每 3 秒检查 `/Applications/WeChat.app` 或 `~/Applications/WeChat.app` 中的微信及辅助进程。使用真实进程路径核对 PID，并在读取连接后重新核对，避免 PID 复用。微信未运行时每 15 秒检查。
- 使用本机 `lsof` 字段输出读取连接目标，不读取聊天记录、消息或传输内容，不上传数据。只添加观察到的公网原生 IPv6 目标；不把 IPv6 套接字中的 IPv4 地址误判为 IPv6。
- 新地址标记“微信自动”，复用现有权限受限的路由服务添加 `/128` 路由。默认 7 天未出现且没有观察到连接时清理。当前连接、手动和停用条目不会被容量淘汰；最多 128 个动态条目，总计最多 256 条。
- 动态地址及发现时间保存在原 `whitelist.json` 中，兼容旧手动数据。自动维护开关和手动移除地址的忽略列表保存在同目录 `wechat-discovery.json`。两者都使用原子写入和 0600 权限。时间戳最多每分钟保存一次，增删立即保存。
- 取消勾选不会被自动重新开启；移除地址会加入忽略列表，可点“恢复忽略地址”重新允许发现。动态条目菜单有“固定为手动条目”。关闭自动维护会请求撤销动态条目的路由，缓存仍保留，手动条目仍生效。
- 扫描失败时保留已有条目，不执行清理，15 秒后重试。上次错误及最后检查时间显示在主窗口。

限制：轮询可能错过短连接和没有可见远端地址的 UDP 流量；首个连接可能需要微信自行重试；本地 HTTP 代理背后的地址无法识别；本功能不禁止 IPv4，不强制微信选择 IPv6。微信内打开网站的 IPv6 也可能被加入，按 IP 安装的路由对所有应用生效。关闭应用会停止发现并清理本应用维护的路由，不安装后台定时任务或登录启动项。

开发验证：

```bash
xcrun swiftc -swift-version 5 Sources/Models.swift Sources/IPv6.swift \
  Sources/SocketClient.swift Sources/CommandRunner.swift Sources/WeChatDiscovery.swift Tests/main.swift -o /tmp/ipv6-discovery-tests
/tmp/ipv6-discovery-tests
/tmp/ipv6-discovery-tests --live  # 只读检查真实微信进程及连接
```


## 1.1.1：长期运行卡住与切换网络修复

- 修复主应用命令执行器中后台 `Process.waitUntilExit` 任务和管道资源积累的问题。改为 `posix_spawn`、非阻塞输出读取和 `waitpid`，每次调用独立回收文件描述符及子进程，不创建 GCD 等待/读取任务。路由辅助程序也使用相同执行器。
- 增加输出大小限制、输入大小限制、子进程组超时终止，以及本地控制 socket 的连接超时。
- 路由状态批量发布到界面，避免每条地址分别触发刷新。
- 每轮最多执行 16 次新增或恢复路由的修改，分批应用大白名单。已有路由冲突不再每个地址各运行一次 netstat。
- 为已启用白名单中的单个目标恢复一种明确失效的主机路由：静态、非接口限定的 `/128` 路由使用 `%en0` 的旧链路本地网关，但出口被系统改为 `utun`，且旧网关不再是当前 en0 默认网关。删除前重新检查唯一性、目标、网关、接口和标志，只恢复这一模式；其他既有路由继续视为冲突，不修改默认路由。

回归测试可在上述测试程序后加 `--stress`：执行 1,000 次正常命令、20 次超时、输出超限、错误退出、子进程继承管道和大输入输出，核对前后文件描述符及线程数。1.1.1 本机测试：描述符 3→3，线程 1→1；辅助程序自测另含失效路由恢复范围的检查。

短时压力测试通过不等同于完成数日持续运行验证。原版本与更新前的用户配置已在本次工作目录备份。
