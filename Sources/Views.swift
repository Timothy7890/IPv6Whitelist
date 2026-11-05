import SwiftUI
import AppKit

private enum UITheme {
    static let accent = Color(red: 0.08, green: 0.59, blue: 0.49)
    static let line = Color.primary.opacity(0.08)
    static let muted = Color.secondary.opacity(0.07)
    static let panel = Color(nsColor: .controlBackgroundColor)
}

struct MainView: View {
    @ObservedObject var model: AppModel
    @State private var search = ""
    @State private var selectedID: UUID?
    @State private var editingEntry: WhitelistEntry?
    @State private var showEditor = false
    @State private var showLogs = false
    @State private var showHelp = false
    @State private var pendingDelete: WhitelistEntry?

    private var filteredEntries: [WhitelistEntry] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return model.entries.filter {
            query.isEmpty || ([$0.name, $0.address] + $0.sources).contains {
                $0.localizedCaseInsensitiveContains(query)
            }
        }
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Rectangle().fill(UITheme.line).frame(width: 1)
            mainContent
        }
        .frame(minWidth: 990, minHeight: 760)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(UITheme.accent)
        .sheet(isPresented: $showEditor) {
            EntryEditorView(entry: editingEntry) { address, name in
                if var entry = editingEntry {
                    if model.entries.contains(where: { $0.id != entry.id && sameIPv6($0.address, address) }) {
                        return "这个 IPv6 地址已经在白名单中了。"
                    }
                    entry.address = address
                    entry.name = name
                    model.updateEntry(entry)
                    return nil
                }
                return model.addEntry(address: address, name: name)
            }
        }
        .sheet(isPresented: $showLogs) { logsSheet }
        .sheet(isPresented: $showHelp) { helpSheet }
        .alert("移除白名单地址？", isPresented: Binding(
            get: { pendingDelete != nil },
            set: { if !$0 { pendingDelete = nil } }
        )) {
            Button("取消", role: .cancel) { pendingDelete = nil }
            Button("移除", role: .destructive) {
                if let entry = pendingDelete { model.deleteEntry(entry) }
                pendingDelete = nil
            }
        } message: {
            Text("移除后停止维护这条路由，并忽略对该地址的自动发现。可通过“恢复忽略地址”重新允许自动发现。")
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 26) {
            HStack(spacing: 11) {
                Image(systemName: "wifi")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 44, height: 44)
                    .background(UITheme.accent.gradient, in: RoundedRectangle(cornerRadius: 13))
                VStack(alignment: .leading, spacing: 4) {
                    Text("Wi-Fi 出口管理").font(.system(size: 15, weight: .semibold))
                    Text("IPv6 · 本地路由工具")
                        .font(.system(size: 10, weight: .medium)).foregroundStyle(.secondary)
                }
            }
            .padding(.top, 8)

            VStack(alignment: .leading, spacing: 8) {
                Text("工作空间").font(.system(size: 10, weight: .semibold)).foregroundStyle(.tertiary)
                    .padding(.horizontal, 10)
                HStack(spacing: 10) {
                    Image(systemName: "checklist").font(.system(size: 15))
                    Text("IPv6 白名单").font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Text("\(model.entries.count)").font(.system(size: 11, weight: .medium, design: .rounded))
                }
                .foregroundStyle(UITheme.accent)
                .padding(.horizontal, 12).padding(.vertical, 11)
                .background(UITheme.accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 9))
                Button { showLogs = true } label: {
                    Label("运行记录", systemImage: "clock.arrow.circlepath")
                        .font(.system(size: 13)).frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12).padding(.vertical, 10)
                }
                .buttonStyle(.plain).foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 12) {
                Label("自动适配 Wi-Fi", systemImage: "arrow.triangle.2.circlepath")
                    .font(.system(size: 12, weight: .semibold))
                Text("开启管理后，切换 Wi-Fi 时会自动读取新网关，更新白名单路由。")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                    .lineSpacing(5).fixedSize(horizontal: false, vertical: true)
                Rectangle().fill(UITheme.line).frame(height: 1)
                HStack {
                    Text("固定网卡").foregroundStyle(.secondary)
                    Spacer()
                    Text("en0").font(.system(size: 11, weight: .medium, design: .monospaced))
                }.font(.system(size: 11))
            }
            .padding(14)
            .background(UITheme.muted, in: RoundedRectangle(cornerRadius: 12))

            Spacer(minLength: 12)

            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 7) {
                    Image(systemName: "cursorarrow.click").font(.system(size: 11))
                    Text("手动启动 · 未启用登录自启").font(.system(size: 10))
                }.foregroundStyle(.tertiary)
                Button { model.copyDirectRules() } label: {
                    Label("复制 Shadowrocket 直连规则", systemImage: "doc.on.doc")
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                }.buttonStyle(.plain)
                Button { model.openDataFolder() } label: {
                    Label("白名单数据文件夹", systemImage: "folder")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }.buttonStyle(.plain)
                Button { showHelp = true } label: {
                    Label("使用说明与隐私", systemImage: "questionmark.circle")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }.buttonStyle(.plain)
            }
        }
        .padding(18)
        .frame(width: 214)
        .frame(maxHeight: .infinity)
        .background(.ultraThinMaterial)
    }

    private var mainContent: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 7) {
                    Text("IPv6 白名单").font(.system(size: 27, weight: .bold))
                    Text("为指定服务器保留 Wi-Fi 直连路径")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer()
                Button { model.importSSH() } label: {
                    Label("导入 SSH", systemImage: "square.and.arrow.down")
                }
                .controlSize(.large).disabled(model.isBusy)
                Button {
                    editingEntry = nil
                    showEditor = true
                } label: { Label("添加地址", systemImage: "plus") }
                .buttonStyle(.borderedProminent).controlSize(.large).disabled(model.isBusy)
                .keyboardShortcut("n", modifiers: .command)
            }

            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 13) {
                    HStack {
                        Label("路由管理", systemImage: "point.3.connected.trianglepath.dotted")
                            .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                        Spacer()
                        Circle().fill(model.isEnabled ? UITheme.accent : Color.secondary.opacity(0.5))
                            .frame(width: 7, height: 7)
                    }
                    HStack(alignment: .center) {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(model.isEnabled ? "已开启" : "未开启")
                                .font(.system(size: 22, weight: .semibold))
                            Text(model.helperReady ? "管理服务已就绪" : "开启管理需要管理员授权")
                                .font(.system(size: 10)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if model.isBusy {
                            ProgressView().controlSize(.small).frame(width: 75)
                        } else {
                            Button(model.isEnabled ? "停止管理" : "开启管理") {
                                if model.isEnabled { model.deactivate() } else { model.activate() }
                            }
                            .buttonStyle(.borderedProminent).controlSize(.regular)
                            .tint(model.isEnabled ? Color.secondary : UITheme.accent)
                        }
                    }
                }
                .padding(17).frame(maxWidth: .infinity, alignment: .leading)
                .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 13))
                .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(UITheme.line))

                VStack(alignment: .leading, spacing: 13) {
                    HStack {
                        Label("当前 Wi-Fi 网关", systemImage: "wifi")
                            .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                        Spacer()
                        Text("en0").font(.system(size: 10, weight: .medium, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    Text(model.gatewayText.isEmpty ? "等待 IPv6 网络" : model.gatewayText)
                        .font(.system(size: 13, weight: .medium, design: .monospaced))
                        .lineLimit(1).minimumScaleFactor(0.7).textSelection(.enabled)
                    Text("随网络变化自动更新")
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                }
                .padding(17).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
                .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 13))
                .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(UITheme.line))
            }
            .fixedSize(horizontal: false, vertical: true)

            if model.broadDefaultGateway != nil { broadDefaultWarning }
            if let error = model.lastError, !error.isEmpty {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.red)
                    Text(error).font(.system(size: 11)).textSelection(.enabled)
                    Spacer(minLength: 0)
                    Button { model.lastError = nil } label: { Image(systemName: "xmark") }
                        .buttonStyle(.plain).foregroundStyle(.secondary).help("关闭错误提示")
                }
                .padding(11)
                .background(Color.red.opacity(0.07), in: RoundedRectangle(cornerRadius: 9))
            }

            weChatPanel

            entriesPanel

            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 5) {
                    Text(model.ipv6ProtectionText.isEmpty ? "白名单外 IPv6 的出口由系统和代理配置决定。" : model.ipv6ProtectionText)
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                    Text("不自动配置代理，也不保证其他 IPv6 已被代理；HTTP 代理应用还需添加 Shadowrocket DIRECT 规则。")
                        .font(.system(size: 10)).foregroundStyle(.tertiary)
                }
                Spacer(minLength: 0)
            }

            HStack(spacing: 8) {
                Circle().fill(model.isEnabled ? UITheme.accent : Color.secondary.opacity(0.5))
                    .frame(width: 5, height: 5)
                Text(model.statusText).lineLimit(1)
                Spacer()
                if !model.lastUpdatedText.isEmpty { Text(model.lastUpdatedText).foregroundStyle(.tertiary) }
                Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.plain).help("刷新状态").disabled(model.isBusy)
            }
            .font(.system(size: 10)).foregroundStyle(.secondary)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var weChatPanel: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                Toggle("自动维护微信 IPv6", isOn: Binding(
                    get: { model.weChatEnabled }, set: { model.setWeChatEnabled($0) }
                )).toggleStyle(.switch).font(.system(size: 12, weight: .semibold))
                Text("自动缓存 \(model.automaticWeChatCount) / 128")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
                if model.ignoredWeChatCount > 0 {
                    Button("恢复忽略地址（\(model.ignoredWeChatCount)）") { model.resetWeChatExclusions() }
                        .controlSize(.small)
                }
                Button("立即检查") { model.scanWeChatNow() }
                    .controlSize(.small).disabled(!model.weChatEnabled || !model.isEnabled)
            }
            HStack {
                Text(model.weChatStatus)
                Spacer()
                if !model.weChatLastScan.isEmpty { Text("最近检查 \(model.weChatLastScan)") }
            }.font(.system(size: 10)).foregroundStyle(.secondary)
            if let error = model.weChatError {
                Text(error).font(.system(size: 10)).foregroundStyle(.red).textSelection(.enabled)
            }
            Text("发现微信进程访问的公网 IPv6 后自动直连，7 天未出现且无连接时清理。首次连接可能需重试；IPv4 不受限制。")
                .font(.system(size: 10)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .background(UITheme.accent.opacity(0.055), in: RoundedRectangle(cornerRadius: 10))
    }

    private var broadDefaultWarning: some View {
        HStack(alignment: .center, spacing: 11) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 18)).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 4) {
                Text("发现 IPv6 默认直连路由").font(.system(size: 12, weight: .semibold))
                Text("其他 IPv6 可能绕过代理。移除默认直连不会自动启用代理，未正确配置时可能无法联网。")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 4)
            Button("移除默认直连") { model.removeBroadDefault() }
                .controlSize(.small).disabled(model.isBusy)
        }
        .padding(13)
        .background(Color.orange.opacity(0.09), in: RoundedRectangle(cornerRadius: 11))
        .overlay(RoundedRectangle(cornerRadius: 11).strokeBorder(Color.orange.opacity(0.22)))
    }

    private var entriesPanel: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text("直连地址").font(.system(size: 13, weight: .semibold))
                Text("\(model.entries.filter(\.enabled).count) / \(model.entries.count) 已选")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
                HStack(spacing: 7) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.tertiary)
                    TextField("搜索名称或 IPv6 地址", text: $search)
                        .textFieldStyle(.plain)
                    if !search.isEmpty {
                        Button { search = "" } label: { Image(systemName: "xmark.circle.fill") }
                            .buttonStyle(.plain).foregroundStyle(.tertiary)
                    }
                }
                .font(.system(size: 11)).padding(.horizontal, 9).padding(.vertical, 7)
                .frame(width: 220)
                .background(UITheme.muted, in: RoundedRectangle(cornerRadius: 7))
            }
            .padding(.horizontal, 16).padding(.vertical, 13)
            Rectangle().fill(UITheme.line).frame(height: 1)
            if filteredEntries.isEmpty {
                VStack(spacing: 11) {
                    Image(systemName: search.isEmpty ? "network" : "magnifyingglass")
                        .font(.system(size: 30, weight: .light)).foregroundStyle(.tertiary)
                    Text(search.isEmpty ? "添加你的第一个 IPv6 地址" : "没有找到匹配地址")
                        .font(.system(size: 13, weight: .medium))
                    Text(search.isEmpty ? "从 SSH 配置导入，或手动添加需要直连的服务器。" : "试试其他名称、地址或来源关键词。")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(30)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(filteredEntries) { entry in
                            entryRow(entry)
                            if entry.id != filteredEntries.last?.id {
                                Rectangle().fill(UITheme.line).frame(height: 1).padding(.leading, 52)
                            }
                        }
                    }
                }
                .frame(maxHeight: .infinity)
            }
            Rectangle().fill(UITheme.line).frame(height: 1)
            HStack {
                Text("每个地址仅添加一条 /128 主机路由")
                Spacer()
                Text("双击条目编辑")
            }
            .font(.system(size: 10)).foregroundStyle(.tertiary)
            .padding(.horizontal, 16).padding(.vertical, 10)
        }
        .frame(maxWidth: .infinity, minHeight: 200, maxHeight: .infinity)
        .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 13))
        .clipShape(RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(UITheme.line))
    }

    private func entryRow(_ entry: WhitelistEntry) -> some View {
        let state = !entry.enabled ? "已停用" : (model.routeStatus[entry.address] ?? (model.isEnabled ? "等待应用" : "待开启"))
        return HStack(spacing: 13) {
            Toggle("启用 \(entry.name.isEmpty ? entry.address : entry.name)", isOn: Binding(
                get: { entry.enabled },
                set: { enabled in
                    var updated = entry
                    updated.enabled = enabled
                    model.updateEntry(updated)
                }
            ))
            .toggleStyle(.checkbox).labelsHidden().disabled(model.isBusy)
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(entry.name.isEmpty ? "未命名服务器" : entry.name)
                        .font(.system(size: 12, weight: .semibold)).lineLimit(1)
                    if !entry.sources.isEmpty {
                        Text(entry.isWeChatAutomatic ? "微信自动" : (entry.sources.contains(where: { $0.lowercased().contains("ssh") }) ? "SSH" : "手动"))
                            .font(.system(size: 8, weight: .semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 5).padding(.vertical, 2)
                            .background(UITheme.muted, in: RoundedRectangle(cornerRadius: 3))
                            .help(entry.sources.joined(separator: "\n"))
                    }
                }
                Text(entry.address)
                    .font(.system(size: 11, weight: .regular, design: .monospaced))
                    .foregroundStyle(.secondary).lineLimit(1).textSelection(.enabled)
            }
            Spacer(minLength: 8)
            HStack(spacing: 5) {
                Circle().fill(routeColor(state, enabled: entry.enabled)).frame(width: 5, height: 5)
                Text(state).font(.system(size: 10)).lineLimit(1)
            }
            .foregroundStyle(routeColor(state, enabled: entry.enabled))
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(routeColor(state, enabled: entry.enabled).opacity(0.07), in: Capsule())
            .frame(maxWidth: 140, alignment: .trailing)
            Menu {
                Button("编辑地址", systemImage: "pencil") { edit(entry) }
                Button("复制 IPv6", systemImage: "doc.on.doc") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(entry.address, forType: .string)
                }
                if entry.isWeChatAutomatic {
                    Button("固定为手动条目", systemImage: "pin") { model.pinWeChatEntry(entry) }
                }
                Divider()
                Button("移出白名单", systemImage: "trash", role: .destructive) { pendingDelete = entry }
            } label: { Image(systemName: "ellipsis").frame(width: 18, height: 22) }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            .disabled(model.isBusy)
        }
        .padding(.horizontal, 16).padding(.vertical, 13)
        .background(selectedID == entry.id ? UITheme.accent.opacity(0.055) : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { if !model.isBusy { edit(entry) } }
        .onTapGesture { selectedID = entry.id }
        .contextMenu {
            Button("编辑地址") { edit(entry) }
            Button("移出白名单", role: .destructive) { pendingDelete = entry }
        }
    }

    private func routeColor(_ status: String, enabled: Bool) -> Color {
        if !enabled { return .secondary }
        if status.contains("失败") || status.contains("错误") { return .red }
        if status.contains("冲突") || status.contains("等待") || status.contains("无网关") { return .orange }
        if model.isEnabled && (status.contains("已") || status.contains("Wi-Fi") || status.contains("直连")) { return UITheme.accent }
        return .secondary
    }

    private func edit(_ entry: WhitelistEntry) {
        editingEntry = entry
        showEditor = true
    }

    private var logsSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("运行记录").font(.title2.weight(.bold))
                    Text("查看本次运行的路由更新与状态变化。")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer()
                Button("完成") { showLogs = false }.keyboardShortcut(.defaultAction)
            }
            ScrollView {
                Text(model.logLines.isEmpty ? "暂无运行记录。" : model.logLines.joined(separator: "\n\n"))
                    .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .topLeading).padding(16)
            }
            .background(UITheme.muted, in: RoundedRectangle(cornerRadius: 10))
        }
        .padding(24).frame(width: 640, height: 420)
    }

    private var helpSheet: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack {
                Text("使用说明与隐私").font(.title2.weight(.bold))
                Spacer()
                Button("完成") { showHelp = false }.keyboardShortcut(.defaultAction)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
            helpItem("bubble.left.and.bubble.right", "微信 IPv6 自动维护", "每 3 秒读取微信及辅助进程的连接目标；微信未运行时每 15 秒检查。最多缓存 128 个动态地址，总白名单上限 256。关闭自动维护会撤销动态路由但保留缓存；手动条目保留。动态地址 7 天未出现且无连接时清理，停用条目不会自动恢复。")
            helpItem("network", "自动发现的范围", "可能包括微信内打开的网站。规则按目标 IP 对整台 Mac 生效。无法识别本地代理背后的目标，也不保证捕获极短连接或所有 UDP 目标。不会强制 IPv6；首次连接可能需要重试。只读取进程路径、连接地址和状态，不读取聊天内容。")
            helpItem("wifi", "切换 Wi-Fi 无需修改地址", "管理运行时会读取 en0 的 IPv6 网关，并更新本应用管理的主机路由。新网络没有 IPv6 时，白名单无法通过 IPv6 直连。")
            helpItem("lock.shield", "白名单地址会看到你的真实出口", "白名单通过 Wi-Fi 直接连接，目标服务器可以看到该网络的公网 IPv6。移除默认直连路由不会自动启用代理；Shadowrocket 未配置好时，白名单外 IPv6 可能不可用。")
            helpItem("doc.on.doc", "系统 HTTP 代理需要额外规则", "使用系统 HTTP/HTTPS 代理的应用会先将请求交给 Shadowrocket，单靠主机路由不能强制这些请求直连。点击“复制 Shadowrocket 直连规则”，将 DIRECT 规则加入其配置，并放在其他可能先匹配的规则之前。")
            helpItem("arrow.down.doc", "SSH 导入可以重复执行", "导入 SSH 配置中的 IPv6 字面地址。重复地址会合并；域名不自动解析。导入仅更新本应用的白名单，不修改 SSH 配置。")
            helpItem("power", "关闭窗口后仍可在菜单栏管理", "停止管理或退出应用时会清理本应用创建的路由。当前为手动启动，没有启用登录自启。")
            helpItem("person.badge.key", "为什么需要管理员授权", "修改系统路由需要管理员权限。管理服务未运行时，开启管理会通过 macOS 授权安装并启动服务；退出应用后服务也会停止。白名单保存在你的电脑上。")
                }
            }
        }
        .padding(26).frame(width: 620, height: 650)
    }

    private func helpItem(_ icon: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 13) {
            Image(systemName: icon).font(.system(size: 17)).foregroundStyle(UITheme.accent).frame(width: 25)
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(detail).font(.system(size: 12)).foregroundStyle(.secondary)
                    .lineSpacing(4).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct EntryEditorView: View {
    let entry: WhitelistEntry?
    let save: (String, String) -> String?
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var address = ""
    @State private var error: String?
    @FocusState private var addressFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 12) {
                Image(systemName: entry == nil ? "plus.circle.fill" : "pencil.circle.fill")
                    .font(.system(size: 32)).foregroundStyle(UITheme.accent)
                VStack(alignment: .leading, spacing: 5) {
                    Text(entry == nil ? "添加直连地址" : "编辑直连地址")
                        .font(.system(size: 21, weight: .bold))
                    Text("仅这个 IPv6 地址通过 Wi-Fi 连接。")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("名称").font(.system(size: 12, weight: .medium))
                TextField("例如：工作服务器", text: $name).textFieldStyle(.roundedBorder).controlSize(.large)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("IPv6 地址").font(.system(size: 12, weight: .medium))
                TextField("2001:db8::1", text: $address)
                    .font(.system(size: 13, design: .monospaced))
                    .textFieldStyle(.roundedBorder).controlSize(.large).focused($addressFocused)
                Text("输入单个 IPv6 地址，可带方括号或 /128，不包含端口。")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.circle.fill")
                    .font(.system(size: 11)).foregroundStyle(.red)
            }
            HStack(alignment: .top, spacing: 7) {
                Image(systemName: "info.circle")
                Text("直连目标可以看到你当前网络的公网 IPv6。开启管理后，已启用的地址才会生效。")
                    .fixedSize(horizontal: false, vertical: true)
            }
            .font(.system(size: 11)).foregroundStyle(.secondary)
            .padding(12).background(UITheme.muted, in: RoundedRectangle(cornerRadius: 9))
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(entry == nil ? "加入白名单" : "保存修改") { commit() }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
            }
        }
        .padding(26).frame(width: 480)
        .tint(UITheme.accent)
        .onAppear {
            name = entry?.name ?? ""
            address = entry?.address ?? ""
            addressFocused = true
        }
    }

    private func commit() {
        let value = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let normalized = canonicalIPv6(value) else {
            error = "请输入可路由的单个 IPv6 地址；不接受本地链路、回环或多播地址。"
            return
        }
        error = save(normalized, name.trimmingCharacters(in: .whitespacesAndNewlines))
        if error == nil { dismiss() }
    }
}

private func sameIPv6(_ lhs: String, _ rhs: String) -> Bool {
    if let left = canonicalIPv6(lhs), let right = canonicalIPv6(rhs) { return left == right }
    return lhs == rhs
}

struct StatusMenuView: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text("Wi-Fi 出口管理")
        Label(model.isEnabled ? "IPv6 白名单管理已开启" : "IPv6 白名单管理未开启", systemImage: model.isEnabled ? "checkmark.circle" : "pause.circle")
        Text("\(model.entries.filter(\.enabled).count) 个地址已启用")
        if model.broadDefaultGateway != nil { Label("存在默认 IPv6 直连路由", systemImage: "exclamationmark.triangle") }
        Divider()
        Button(model.isEnabled ? "停止管理" : "开启管理") {
            if model.isEnabled { model.deactivate() } else { model.activate() }
        }.disabled(model.isBusy)
        Button("打开白名单窗口") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }.keyboardShortcut("o", modifiers: .command)
        Button("刷新状态") { model.refresh() }.disabled(model.isBusy)
        Divider()
        Button("退出 Wi-Fi 出口管理") { NSApp.terminate(nil) }.keyboardShortcut("q", modifiers: .command)
    }
}
