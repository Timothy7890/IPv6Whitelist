import SwiftUI

struct SSHSyncView: View {
    @ObservedObject var sync: SSHSyncModel
    @State private var showAdd = false
    @State private var showToken = false
    @State private var confirmInclude = false
    @State private var controllerText = ""
    @State private var proxyText = ""
    @State private var pendingRemove: SSHMapping?
    @State private var mappingSearch = ""
    @State private var editingJump: UUID?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            HStack(alignment: .top, spacing: 12) {
                connectionCard
                includeCard
            }
            .fixedSize(horizontal: false, vertical: true)
            if let error = sync.errorText {
                message(error, systemImage: "exclamationmark.triangle.fill", color: .orange)
            } else if let notice = sync.noticeText {
                message(notice, systemImage: "checkmark.circle.fill", color: UITheme.accent)
            }
            mappingList
            footer
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear {
            controllerText = sync.settings.controllerURL
            proxyText = sync.settings.socksProxy ?? ""
            sync.reloadLocalState()
            if sync.hasToken, sync.lastFetched == nil { Task { await sync.refresh() } }
        }
        .sheet(isPresented: $showAdd) { SSHMappingEditor(sync: sync) }
        .sheet(isPresented: $showToken) { SSHTokenEditor(sync: sync) }
        .alert("修改 ~/.ssh/config？", isPresented: $confirmInclude) {
            Button("取消", role: .cancel) {}
            Button("备份并添加") { sync.enableInclude() }
        } message: {
            Text("会先备份原文件，再在最顶部加入一行：\n\(sync.paths.includeLine)\n\n其余内容保持不变。之后 App 只修改生成的文件；删除这一行即可恢复。")
        }
        .alert("移除这个 Host 的动态更新？", isPresented: Binding(
            get: { pendingRemove != nil },
            set: { if !$0 { pendingRemove = nil } }
        )) {
            Button("取消", role: .cancel) { pendingRemove = nil }
            Button("移除", role: .destructive) {
                if let mapping = pendingRemove { sync.removeMapping(mapping) }
                pendingRemove = nil
            }
        } message: {
            Text("移除后该 Host 恢复使用 ~/.ssh/config 中原有的 HostName。")
        }
    }

    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 7) {
                Text("SSH Config 更新").font(.system(size: 27, weight: .bold))
                Text("根据 netbridge 上报的地址，更新指定 Host 的 HostName")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Spacer()
            Button { showAdd = true } label: { Label("添加 Host", systemImage: "plus") }
                .controlSize(.large).disabled(sync.devices.isEmpty)
            Button {
                saveConnection()
                Task { await sync.updateAll() }
            } label: {
                Label(sync.pendingCount > 0 ? "一键更新（\(sync.pendingCount)）" : "一键更新",
                      systemImage: "arrow.triangle.2.circlepath")
            }
            .buttonStyle(.borderedProminent).controlSize(.large)
            .disabled(sync.isBusy || !sync.hasToken || sync.includeStatus != .active || sync.settings.mappings.isEmpty)
        }
    }

    private var connectionCard: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Label("netbridge 连接", systemImage: "network")
                    .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                Spacer()
                Circle().fill(sync.lastFetched != nil && sync.errorText == nil ? UITheme.accent : Color.secondary.opacity(0.5))
                    .frame(width: 7, height: 7)
            }
            TextField("https://…", text: $controllerText)
                .textFieldStyle(.roundedBorder).font(.system(size: 11, design: .monospaced))
                .onSubmit { saveConnection() }
            HStack(spacing: 8) {
                TextField("SOCKS5 代理，可选择或填写，如 127.0.0.1:1085", text: $proxyText)
                    .textFieldStyle(.roundedBorder).font(.system(size: 11, design: .monospaced))
                    .onSubmit { saveConnection() }
                Menu(proxyMenuTitle) {
                    Button("直连（不使用代理）") { chooseProxy("") }
                    Divider()
                    ForEach(socksProxyPresets) { preset in
                        Button("\(preset.name)（\(String(preset.port))）") { chooseProxy(preset.address) }
                    }
                }
                .controlSize(.small).fixedSize()
            }
            HStack {
                Text(sync.hasToken ? "只读令牌已保存在钥匙串" : "尚未设置只读令牌")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
                Button(sync.hasToken ? "更换令牌" : "设置令牌") { showToken = true }.controlSize(.small)
                Button("刷新") {
                    saveConnection()
                    Task { await sync.refresh() }
                }
                .controlSize(.small).disabled(sync.isBusy || !sync.hasToken)
            }
        }
        .padding(15).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(UITheme.line))
    }

    private var proxyMenuTitle: String {
        if proxyText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "直连" }
        return socksProxyPreset(matching: proxyText)?.name ?? "自定义"
    }

    private func chooseProxy(_ address: String) {
        proxyText = address
        saveConnection()
        if sync.hasToken { Task { await sync.refresh() } }
    }

    private func saveConnection() {
        sync.setConnection(controller: controllerText, socksProxy: proxyText)
    }

    private var includeCard: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Label("SSH 配置", systemImage: "doc.text")
                    .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                Spacer()
                Circle().fill(sync.includeStatus == .active ? UITheme.accent : Color.orange).frame(width: 7, height: 7)
            }
            Text(includeTitle).font(.system(size: 17, weight: .semibold))
            HStack {
                Text(includeDetail).font(.system(size: 10)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                if sync.includeStatus == .missing {
                    Button("启用") { confirmInclude = true }.controlSize(.small)
                }
            }
        }
        .padding(15).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(UITheme.line))
    }

    private var includeTitle: String {
        switch sync.includeStatus {
        case .active: return "已启用"
        case .missing: return "未启用"
        case .misplaced: return "位置不对"
        }
    }

    private var includeDetail: String {
        switch sync.includeStatus {
        case .active: return "地址写入 ~/.ssh/config.d/netbridge-dynamic，优先于主配置"
        case .missing: return "需要在 ~/.ssh/config 顶部加一行 Include"
        case .misplaced: return "Include 必须放在所有 Host 之前，请手动移到文件最顶部"
        }
    }

    private func message(_ text: String, systemImage: String, color: Color) -> some View {
        Label(text, systemImage: systemImage)
            .font(.system(size: 11)).foregroundStyle(color).textSelection(.enabled)
    }

    private var mappingList: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("动态更新的 Host").font(.system(size: 14, weight: .semibold))
                Text("\(sync.settings.mappings.count) 个").font(.system(size: 11)).foregroundStyle(.secondary)
                Spacer()
                if sync.isBusy { ProgressView().controlSize(.small) }
                if !sync.settings.mappings.isEmpty {
                    SSHSearchField(placeholder: "搜索 Host、设备或地址", text: $mappingSearch).frame(width: 230)
                }
            }
            .padding(.horizontal, 17).padding(.vertical, 13)
            Rectangle().fill(UITheme.line).frame(height: 1)
            if sync.settings.mappings.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "server.rack").font(.system(size: 26)).foregroundStyle(.tertiary)
                    Text(sync.hasToken ? "点击“添加 Host”，选择要动态更新的 B 端设备" : "先设置只读令牌，读取在线设备")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(filterSSHMappings(sync.settings.mappings, query: mappingSearch)) { mapping in
                            mappingRow(mapping)
                            Rectangle().fill(UITheme.line).frame(height: 1)
                        }
                        if filterSSHMappings(sync.settings.mappings, query: mappingSearch).isEmpty {
                            Text("没有匹配的 Host").font(.system(size: 12)).foregroundStyle(.secondary).padding(30)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(UITheme.line))
    }

    private func mappingRow(_ mapping: SSHMapping) -> some View {
        HStack(alignment: .center, spacing: 14) {
            VStack(alignment: .leading, spacing: 5) {
                Text(mapping.hostAlias).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Text(mapping.deviceLabel).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
            }
            .frame(width: 130, alignment: .leading)
            Picker("", selection: Binding(
                get: { mapping.policy },
                set: { sync.setPolicy($0, for: mapping) }
            )) {
                ForEach(SSHAddressPolicy.allCases) { Text($0.title).tag($0) }
            }
            .labelsHidden().controlSize(.small).frame(width: 135)
            jumpButton(mapping)
            addressColumn(mapping)
            Spacer(minLength: 6)
            stateBadge(sync.state(of: mapping))
            Button { pendingRemove = mapping } label: { Image(systemName: "trash") }
                .buttonStyle(.plain).foregroundStyle(.secondary).help("移除")
        }
        .padding(.horizontal, 17).padding(.vertical, 11)
    }

    private func jumpLabel(_ mapping: SSHMapping) -> String {
        switch mapping.proxyJump {
        case sshProxyJumpNone?: return "直连"
        case let jump?: return jump
        case nil:
            let host = sync.effectiveHost(for: mapping.hostAlias)
            if host?.usesProxyCommand == true { return "沿用：ProxyCommand" }
            if let jump = host?.proxyJump, jump != sshProxyJumpNone { return "沿用：\(jump)" }
            return "沿用：直连"
        }
    }

    private func jumpButton(_ mapping: SSHMapping) -> some View {
        Button { editingJump = mapping.id } label: {
            HStack(spacing: 5) {
                Image(systemName: "arrow.triangle.turn.up.right.diamond").font(.system(size: 10))
                Text(jumpLabel(mapping)).font(.system(size: 11)).lineLimit(1).truncationMode(.middle)
            }
            .frame(width: 125, alignment: .leading)
        }
        .controlSize(.small)
        .help("跳板（ProxyJump）")
        .popover(isPresented: Binding(
            get: { editingJump == mapping.id },
            set: { if !$0 { editingJump = nil } }
        )) {
            VStack(alignment: .leading, spacing: 10) {
                SSHJumpList(
                    hosts: sync.hosts.filter { $0.alias != mapping.hostAlias && isSafeSSHAlias($0.alias) },
                    selection: Binding(
                        get: { mapping.proxyJump },
                        set: { jump in
                            sync.setProxyJump(jump, for: mapping)
                            editingJump = nil
                        }
                    )
                )
            }
            .padding(14).frame(width: 400)
        }
    }

    private func addressColumn(_ mapping: SSHMapping) -> some View {
        let current = mapping.applied?.display ?? sync.effectiveHost(for: mapping.hostAlias)?.display ?? "未配置"
        let state = sync.state(of: mapping)
        return VStack(alignment: .leading, spacing: 4) {
            Text(current).font(.system(size: 11, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                .foregroundStyle(.secondary).textSelection(.enabled)
            if case .pending(let target) = state {
                Text("→ \(target.display)").font(.system(size: 11, weight: .medium, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle).foregroundStyle(UITheme.accent).textSelection(.enabled)
            }
        }
        .frame(minWidth: 180, maxWidth: .infinity, alignment: .leading)
    }

    private func stateBadge(_ state: SSHMappingState) -> some View {
        let (text, color): (String, Color)
        switch state {
        case .upToDate: (text, color) = ("已是最新", UITheme.accent)
        case .pending: (text, color) = ("待更新", .blue)
        case .offline: (text, color) = ("设备离线", .secondary)
        case .noAddress: (text, color) = ("无此类地址", .orange)
        }
        return Text(text).font(.system(size: 10, weight: .medium)).foregroundStyle(color)
            .padding(.horizontal, 9).padding(.vertical, 4)
            .background(color.opacity(0.1), in: Capsule())
    }

    private var footer: some View {
        HStack {
            Text("设备离线时保留上次地址。IP 变化不会要求重新信任主机，但 Host 第一次走这里更新时会询问一次主机指纹。")
                .font(.system(size: 10)).foregroundStyle(.secondary)
            Spacer()
            if let date = sync.lastFetched {
                Text("读取于 \(date.formatted(date: .omitted, time: .standard))")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
            }
            Button("显示生成的文件") { sync.revealGeneratedFile() }
                .buttonStyle(.plain).font(.system(size: 10)).foregroundStyle(.secondary)
                .disabled(!FileManager.default.fileExists(atPath: sync.paths.dynamic.path))
        }
    }
}

private struct SSHSearchField: View {
    var placeholder: String
    @Binding var text: String

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass").font(.system(size: 11)).foregroundStyle(.secondary)
            TextField(placeholder, text: $text).textFieldStyle(.plain).font(.system(size: 12))
            if !text.isEmpty {
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.tertiary).help("清除")
            }
        }
        .padding(.horizontal, 9).padding(.vertical, 6)
        .background(UITheme.muted, in: RoundedRectangle(cornerRadius: 7))
    }
}

private struct SSHHostRow: View {
    var title: String
    var detail: String
    var selected: Bool
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 12))
                    .foregroundStyle(selected ? UITheme.accent : Color.secondary.opacity(0.5))
                Text(title).font(.system(size: 12, weight: .medium)).lineLimit(1)
                Spacer(minLength: 12)
                Text(detail).font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background(selected ? UITheme.accent.opacity(0.10) : Color.clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Keep the main config's jump, connect directly, or pick a Host. Searching
/// narrows the Hosts only, so the first two stay one click away.
struct SSHJumpList: View {
    var hosts: [SSHEffectiveHost]
    @Binding var selection: String?
    var listHeight: CGFloat = 230
    @State private var search = ""

    var body: some View {
        let matches = filterSSHHosts(hosts, query: search)
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("跳板（ProxyJump）").font(.system(size: 12, weight: .medium))
                Text("\(matches.count) / \(hosts.count)").font(.system(size: 10)).foregroundStyle(.secondary)
            }
            SSHSearchField(placeholder: "搜索跳板 Host 或地址", text: $search)
            VStack(spacing: 0) {
                SSHHostRow(title: "沿用主配置", detail: "默认", selected: selection == nil) { selection = nil }
                SSHHostRow(title: "直连", detail: "不走跳板", selected: selection == sshProxyJumpNone) { selection = sshProxyJumpNone }
                Rectangle().fill(UITheme.line).frame(height: 1)
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(matches) { host in
                            SSHHostRow(title: host.alias, detail: host.display, selected: selection == host.alias) {
                                selection = host.alias
                            }
                        }
                        if matches.isEmpty {
                            Text("没有匹配的 Host").font(.system(size: 11)).foregroundStyle(.secondary).padding(18)
                        }
                    }
                }
                .frame(height: listHeight)
            }
            .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(UITheme.line))
        }
    }
}

struct SSHMappingEditor: View {
    @ObservedObject var sync: SSHSyncModel
    @Environment(\.dismiss) private var dismiss
    @State private var deviceID = ""
    @State private var alias = ""
    @State private var policy = SSHAddressPolicy.lanIPv4
    @State private var forwardTarget = ""
    @State private var error: String?
    @State private var hostSearch = ""
    @State private var proxyJump: String?

    private var device: NetbridgeDevice? { sync.devices.first { $0.keyID == deviceID } }
    private var aliases: [SSHEffectiveHost] { sync.hosts.filter { !sync.mappedAliases.contains($0.alias) && isSafeSSHAlias($0.alias) } }

    private var preview: String {
        guard let device else { return "—" }
        let mapping = SSHMapping(keyID: device.keyID, deviceLabel: device.label, hostAlias: alias, policy: policy,
                                 forwardTarget: policy == .tunnelEntry ? forwardTarget : nil)
        return resolveSSHTarget(mapping, device: device)?.display ?? "这台设备没有上报这类地址"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("添加 Host").font(.title2.weight(.bold))
            Form {
                Picker("B 端设备", selection: $deviceID) {
                    ForEach(sync.devices) { Text($0.label).tag($0.keyID) }
                }
                Picker("地址类型", selection: $policy) {
                    ForEach(SSHAddressPolicy.allCases) { Text($0.title).tag($0) }
                }
                if policy == .tunnelEntry {
                    Picker("转发目标", selection: $forwardTarget) {
                        ForEach(device?.forwards ?? []) {
                            Text("\($0.localAddress)（\($0.publicAddress)）").tag($0.localAddress)
                        }
                    }
                }
                LabeledContent("将写入") {
                    Text(preview).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                }
            }
            hostPicker
            SSHJumpList(
                hosts: sync.hosts.filter { $0.alias != alias && isSafeSSHAlias($0.alias) },
                selection: $proxyJump,
                listHeight: 110
            )
            if let error {
                Text(error).font(.system(size: 11)).foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("添加") {
                    guard let device else { return }
                    error = sync.addMapping(device: device, alias: alias, policy: policy,
                                            forwardTarget: forwardTarget.isEmpty ? nil : forwardTarget,
                                            proxyJump: proxyJump)
                    if error == nil { dismiss() }
                }
                .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
                .disabled(device == nil || alias.isEmpty)
            }
        }
        .padding(24).frame(width: 520)
        .onAppear {
            deviceID = sync.devices.first?.keyID ?? ""
            alias = aliases.first(where: { $0.alias == device?.label })?.alias ?? aliases.first?.alias ?? ""
            selectDefaultForward()
        }
        .onChange(of: deviceID) { selectDefaultForward() }
    }

    private var hostPicker: some View {
        let matches = filterSSHHosts(aliases, query: hostSearch)
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("SSH Host").font(.system(size: 12, weight: .medium))
                Text("\(matches.count) / \(aliases.count)").font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
                if !alias.isEmpty {
                    Text("已选：\(alias)").font(.system(size: 11, weight: .medium))
                        .foregroundStyle(UITheme.accent).lineLimit(1)
                }
            }
            SSHSearchField(placeholder: "搜索 Host 名称或地址，可用空格分隔多个词", text: $hostSearch)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(matches) { host in
                        SSHHostRow(title: host.alias, detail: host.display, selected: alias == host.alias) {
                            alias = host.alias
                        }
                    }
                    if matches.isEmpty {
                        Text("没有匹配的 Host").font(.system(size: 11)).foregroundStyle(.secondary).padding(24)
                    }
                }
            }
            .frame(height: 150)
            .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(UITheme.line))
        }
    }

    private func selectDefaultForward() {
        let forwards = device?.forwards ?? []
        forwardTarget = (forwards.first { $0.localAddress.hasSuffix(":22") } ?? forwards.first)?.localAddress ?? ""
    }
}

private struct SSHTokenEditor: View {
    @ObservedObject var sync: SSHSyncModel
    @Environment(\.dismiss) private var dismiss
    @State private var token = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("netbridge 只读令牌").font(.title2.weight(.bold))
            Text("只能读取在线设备和地址，不能修改任何东西。令牌只保存在这台 Mac 的钥匙串里。")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            SecureField("粘贴令牌", text: $token).textFieldStyle(.roundedBorder)
            if let error {
                Text(error).font(.system(size: 11)).foregroundStyle(.orange)
            }
            HStack {
                if sync.hasToken {
                    Button("删除令牌", role: .destructive) {
                        sync.deleteToken()
                        dismiss()
                    }
                }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("保存") {
                    error = sync.setToken(token)
                    if error == nil { dismiss() }
                }
                .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).disabled(token.isEmpty)
            }
        }
        .padding(24).frame(width: 460)
    }
}
