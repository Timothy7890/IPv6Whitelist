import SwiftUI

struct SSHSyncView: View {
    @ObservedObject var sync: SSHSyncModel
    @State private var showAdd = false
    @State private var showToken = false
    @State private var confirmInclude = false
    @State private var controllerText = ""
    @State private var pendingRemove: SSHMapping?

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
                sync.setController(controllerText)
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
                .onSubmit { sync.setController(controllerText) }
            HStack {
                Text(sync.hasToken ? "只读令牌已保存在钥匙串" : "尚未设置只读令牌")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
                Button(sync.hasToken ? "更换令牌" : "设置令牌") { showToken = true }.controlSize(.small)
                Button("刷新") {
                    sync.setController(controllerText)
                    Task { await sync.refresh() }
                }
                .controlSize(.small).disabled(sync.isBusy || !sync.hasToken)
            }
        }
        .padding(15).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).strokeBorder(UITheme.line))
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
                        ForEach(sync.settings.mappings) { mapping in
                            mappingRow(mapping)
                            Rectangle().fill(UITheme.line).frame(height: 1)
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
            addressColumn(mapping)
            Spacer(minLength: 6)
            stateBadge(sync.state(of: mapping))
            Button { pendingRemove = mapping } label: { Image(systemName: "trash") }
                .buttonStyle(.plain).foregroundStyle(.secondary).help("移除")
        }
        .padding(.horizontal, 17).padding(.vertical, 11)
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

struct SSHMappingEditor: View {
    @ObservedObject var sync: SSHSyncModel
    @Environment(\.dismiss) private var dismiss
    @State private var deviceID = ""
    @State private var alias = ""
    @State private var policy = SSHAddressPolicy.lanIPv4
    @State private var forwardTarget = ""
    @State private var error: String?

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
                Picker("SSH Host", selection: $alias) {
                    ForEach(aliases) { Text("\($0.alias)   \($0.display)").tag($0.alias) }
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
            if let error {
                Text(error).font(.system(size: 11)).foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("添加") {
                    guard let device else { return }
                    error = sync.addMapping(device: device, alias: alias, policy: policy,
                                            forwardTarget: forwardTarget.isEmpty ? nil : forwardTarget)
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
