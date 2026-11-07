import SwiftUI
import AppKit

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
    @State private var expandedGroups = Set<UUID>()
    @State private var editingGroup: SSHJumpGroup?
    @State private var pendingRemoveGroup: SSHJumpGroup?

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
        .sheet(item: $editingGroup) { SSHMappingEditor(sync: sync, editing: $0) }
        .alert("移除这个组合？", isPresented: Binding(
            get: { pendingRemoveGroup != nil },
            set: { if !$0 { pendingRemoveGroup = nil } }
        )) {
            Button("取消", role: .cancel) { pendingRemoveGroup = nil }
            Button("移除", role: .destructive) {
                if let group = pendingRemoveGroup { sync.removeJumpGroup(group) }
                pendingRemoveGroup = nil
            }
        } message: {
            Text("组合里的 \(pendingRemoveGroup?.members.count ?? 0) 个 Host 都会恢复使用 ~/.ssh/config 中原有的跳板设置。")
        }
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
                .controlSize(.large).disabled(sync.devices.isEmpty && sync.hosts.isEmpty)
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
                        ForEach(visibleRows) { row in
                            switch row {
                            case .single(let mapping): mappingRow(mapping)
                            case .group(let group): groupRow(group)
                            }
                            Rectangle().fill(UITheme.line).frame(height: 1)
                        }
                        if visibleRows.isEmpty {
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

    /// A group stays whole when any member matches, so its jump is never edited
    /// while part of it is hidden.
    private var visibleRows: [SSHMappingRow] {
        let matched = Set(filterSSHMappings(sync.settings.mappings, query: mappingSearch).map(\.id))
        return sshMappingRows(sync.settings.mappings).filter { row in
            switch row {
            case .single(let mapping): return matched.contains(mapping.id)
            case .group(let group): return group.members.contains { matched.contains($0.id) }
            }
        }
    }

    private func groupRow(_ group: SSHJumpGroup) -> some View {
        let expanded = expandedGroups.contains(group.id) || !mappingSearch.isEmpty
        return VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 14) {
                Button {
                    if expandedGroups.remove(group.id) == nil { expandedGroups.insert(group.id) }
                } label: {
                    HStack(spacing: 7) {
                        Image(systemName: expanded ? "chevron.down" : "chevron.right")
                            .font(.system(size: 9, weight: .semibold)).foregroundStyle(.secondary).frame(width: 10)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(group.title).font(.system(size: 13, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                            Text(sshJumpOnlyLabel).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .frame(width: 282, alignment: .leading)
                groupJumpButton(group)
                Text(group.aliases.joined(separator: "、"))
                    .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                    .help(group.aliases.joined(separator: "\n"))
                    .frame(minWidth: 180, maxWidth: .infinity, alignment: .leading)
                Spacer(minLength: 6)
                Text("组合").font(.system(size: 10, weight: .medium)).foregroundStyle(UITheme.accent)
                    .padding(.horizontal, 9).padding(.vertical, 4)
                    .background(UITheme.accent.opacity(0.1), in: Capsule())
                Button { editingGroup = group } label: { Image(systemName: "pencil") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).help("编辑组合")
                Button { pendingRemoveGroup = group } label: { Image(systemName: "trash") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).help("移除组合")
            }
            .padding(.horizontal, 17).padding(.vertical, 11)
            if expanded {
                VStack(spacing: 0) {
                    ForEach(group.members) { member in
                        HStack(spacing: 14) {
                            Text(member.hostAlias).font(.system(size: 11, weight: .medium)).lineLimit(1)
                                .frame(width: 180, alignment: .leading)
                            Text(sync.effectiveHost(for: member.hostAlias)?.display ?? "未配置")
                                .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                                .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                            Spacer()
                        }
                        .padding(.vertical, 5)
                    }
                }
                .padding(.leading, 34).padding(.trailing, 17).padding(.bottom, 9)
            }
        }
    }

    private func groupJumpButton(_ group: SSHJumpGroup) -> some View {
        Button { editingJump = group.id } label: {
            HStack(spacing: 5) {
                Image(systemName: "arrow.triangle.turn.up.right.diamond").font(.system(size: 10))
                Text(group.proxyJump == sshProxyJumpNone ? "直连" : group.proxyJump ?? "未设置")
                    .font(.system(size: 11)).lineLimit(1).truncationMode(.middle)
            }
            .frame(width: 125, alignment: .leading)
        }
        .controlSize(.small)
        .help("整个组合的跳板（ProxyJump）")
        .popover(isPresented: Binding(
            get: { editingJump == group.id },
            set: { if !$0 { editingJump = nil } }
        )) {
            VStack(alignment: .leading, spacing: 10) {
                Text("修改后组合里的 \(group.members.count) 个 Host 一起生效")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                SSHJumpList(
                    hosts: sync.hosts.filter { !group.aliases.contains($0.alias) && isSafeSSHAlias($0.alias) },
                    selection: Binding(
                        get: { group.proxyJump },
                        set: { jump in
                            sync.errorText = sync.saveJumpGroup(id: group.id, aliases: group.aliases, proxyJump: jump)
                            editingJump = nil
                        }
                    ),
                    autoFocus: true
                )
            }
            .padding(14).frame(width: 400)
        }
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
                    ),
                    autoFocus: true
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
        case .jumpOnly: (text, color) = ("仅跳板", .secondary)
        }
        return Text(text).font(.system(size: 10, weight: .medium)).foregroundStyle(color)
            .padding(.horizontal, 9).padding(.vertical, 4)
            .background(color.opacity(0.1), in: Capsule())
    }

    private var footer: some View {
        HStack {
            Text("设备离线时保留上次地址。公网 IPv6 会自动加入白名单。IP 变化不会要求重新信任主机，但 Host 第一次走这里更新时会询问一次主机指纹。")
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

/// A plain NSTextField because the arrow keys must reach the list while typing
/// continues, and they must stay with the input method while it is composing:
/// AppKit only sends these commands when no composition is using them.
private struct SSHSearchTextField: NSViewRepresentable {
    var placeholder: String
    @Binding var text: String
    var autoFocus: Bool
    var onMove: ((Int) -> Void)?
    var onReturn: (() -> Bool)?

    final class Field: NSTextField {
        var autoFocus = false
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard autoFocus, window != nil else { return }
            autoFocus = false
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.window?.makeFirstResponder(self)
            }
        }
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: SSHSearchTextField
        init(_ parent: SSHSearchTextField) { self.parent = parent }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSTextField else { return }
            parent.text = field.stringValue
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            switch selector {
            case #selector(NSResponder.moveDown(_:)):
                guard let onMove = parent.onMove else { return false }
                onMove(1)
                return true
            case #selector(NSResponder.moveUp(_:)):
                guard let onMove = parent.onMove else { return false }
                onMove(-1)
                return true
            case #selector(NSResponder.insertNewline(_:)):
                return parent.onReturn?() ?? false
            default:
                return false
            }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> Field {
        let field = Field()
        field.autoFocus = autoFocus
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.font = .systemFont(ofSize: 12)
        field.placeholderString = placeholder
        field.lineBreakMode = .byTruncatingTail
        field.cell?.usesSingleLineMode = true
        field.delegate = context.coordinator
        return field
    }

    func updateNSView(_ field: Field, context: Context) {
        context.coordinator.parent = self
        if field.placeholderString != placeholder { field.placeholderString = placeholder }
        let composing = (field.currentEditor() as? NSTextView)?.hasMarkedText() ?? false
        if !composing, field.stringValue != text { field.stringValue = text }
    }
}

private struct SSHSearchField: View {
    var placeholder: String
    @Binding var text: String
    var autoFocus = false
    var onMove: ((Int) -> Void)? = nil
    var onReturn: (() -> Bool)? = nil

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass").font(.system(size: 11)).foregroundStyle(.secondary)
            SSHSearchTextField(placeholder: placeholder, text: $text, autoFocus: autoFocus,
                               onMove: onMove, onReturn: onReturn)
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
    var highlighted = false
    var multiple = false
    var action: () -> Void

    private var icon: String {
        if multiple { return selected ? "checkmark.square.fill" : "square" }
        return selected ? "checkmark.circle.fill" : "circle"
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 12))
                    .foregroundStyle(selected ? UITheme.accent : Color.secondary.opacity(0.5))
                Text(title).font(.system(size: 12, weight: .medium)).lineLimit(1)
                Spacer(minLength: 12)
                Text(detail).font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background(highlighted ? UITheme.accent.opacity(0.24) : selected ? UITheme.accent.opacity(0.10) : Color.clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Keep the main config's jump, connect directly, or pick a Host. Searching
/// narrows the Hosts only, so the first two stay one click away.
struct SSHJumpList: View {
    // Control characters cannot appear in an alias, so these never collide with one.
    private static let inheritRow = "\u{1}inherit"
    private static let directRow = "\u{1}direct"

    var hosts: [SSHEffectiveHost]
    @Binding var selection: String?
    var listHeight: CGFloat = 230
    var autoFocus = false
    @State private var search = ""
    @State private var highlighted: String?

    private var matches: [SSHEffectiveHost] { filterSSHHosts(hosts, query: search) }

    /// While searching, the keys go straight to the results.
    private var keyboardRows: [String] {
        let aliases = matches.map(\.alias)
        return search.isEmpty ? [Self.inheritRow, Self.directRow] + aliases : aliases
    }

    private func choose(_ row: String) {
        switch row {
        case Self.inheritRow: selection = nil
        case Self.directRow: selection = sshProxyJumpNone
        default: selection = row
        }
    }

    private func pressReturn() -> Bool {
        if let highlighted {
            choose(highlighted)
            return true
        }
        if search.isEmpty { return false }
        // Choosing a jump writes the config, so only an unambiguous result is picked.
        if matches.count == 1 { choose(matches[0].alias) }
        return true
    }

    var body: some View {
        let matches = self.matches
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("跳板（ProxyJump）").font(.system(size: 12, weight: .medium))
                Text("\(matches.count) / \(hosts.count)").font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
                Text("↑↓ 选择  ⏎ 确认").font(.system(size: 10)).foregroundStyle(.tertiary)
            }
            SSHSearchField(placeholder: "搜索跳板 Host 或地址", text: $search, autoFocus: autoFocus,
                           onMove: { highlighted = movedHighlight(current: highlighted, items: keyboardRows, delta: $0) },
                           onReturn: pressReturn)
            VStack(spacing: 0) {
                SSHHostRow(title: "沿用主配置", detail: "默认", selected: selection == nil,
                           highlighted: highlighted == Self.inheritRow) { selection = nil }
                SSHHostRow(title: "直连", detail: "不走跳板", selected: selection == sshProxyJumpNone,
                           highlighted: highlighted == Self.directRow) { selection = sshProxyJumpNone }
                Rectangle().fill(UITheme.line).frame(height: 1)
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(matches) { host in
                                SSHHostRow(title: host.alias, detail: host.display, selected: selection == host.alias,
                                           highlighted: highlighted == host.alias) {
                                    selection = host.alias
                                }
                                .id(host.alias)
                            }
                            if matches.isEmpty {
                                Text("没有匹配的 Host").font(.system(size: 11)).foregroundStyle(.secondary).padding(18)
                            }
                        }
                    }
                    .frame(height: listHeight)
                    .onChange(of: highlighted) {
                        if let highlighted, hosts.contains(where: { $0.alias == highlighted }) { proxy.scrollTo(highlighted) }
                    }
                }
            }
            .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(UITheme.line))
        }
        .onChange(of: search) { highlighted = nil }
    }
}

struct SSHMappingEditor: View {
    // Control characters cannot appear in a key ID, so this never collides with one.
    private static let noRemoteID = "\u{1}no-remote"

    @ObservedObject var sync: SSHSyncModel
    /// Editing an existing group instead of adding a Host.
    var editing: SSHJumpGroup? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var deviceID = ""
    @State private var alias = ""
    @State private var policy = SSHAddressPolicy.lanIPv4
    @State private var forwardTarget = ""
    @State private var error: String?
    @State private var hostSearch = ""
    @State private var highlightedHost: String?
    @State private var proxyJump: String?
    @State private var checkedAliases = Set<String>()

    private var isNoRemote: Bool { deviceID == Self.noRemoteID }
    private var sortedChecked: [String] {
        checkedAliases.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }
    private var device: NetbridgeDevice? { sync.devices.first { $0.keyID == deviceID } }
    private var aliases: [SSHEffectiveHost] {
        sync.hosts.filter { host in
            (!sync.mappedAliases.contains(host.alias) || editing?.aliases.contains(host.alias) == true) && isSafeSSHAlias(host.alias)
        }
    }

    private var preview: String {
        guard let device else { return "—" }
        let mapping = SSHMapping(keyID: device.keyID, deviceLabel: device.label, hostAlias: alias, policy: policy,
                                 forwardTarget: policy == .tunnelEntry ? forwardTarget : nil)
        return resolveSSHTarget(mapping, device: device)?.display ?? "这台设备没有上报这类地址"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(editing == nil ? "添加 Host" : "编辑组合").font(.title2.weight(.bold))
            Form {
                if editing == nil {
                    Picker("B 端设备", selection: $deviceID) {
                        ForEach(sync.devices) { Text($0.label).tag($0.keyID) }
                        if !sync.devices.isEmpty { Divider() }
                        Text(sshJumpOnlyLabel).tag(Self.noRemoteID)
                    }
                }
                if isNoRemote {
                    LabeledContent("将写入") {
                        Text("只写入跳板，不更新地址").font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                } else {
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
            }
            hostPicker
            SSHJumpList(
                hosts: sync.hosts.filter { host in
                    isSafeSSHAlias(host.alias) && (isNoRemote ? !checkedAliases.contains(host.alias) : host.alias != alias)
                },
                selection: $proxyJump,
                listHeight: 110
            )
            if let error {
                Text(error).font(.system(size: 11)).foregroundStyle(.orange)
            } else if isNoRemote, !checkedAliases.isEmpty, proxyJump == nil {
                Text("“沿用主配置”不会写入任何内容，请选择跳板或直连。")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(confirmTitle) {
                    if let editing {
                        error = sync.saveJumpGroup(id: editing.id, aliases: sortedChecked, proxyJump: proxyJump)
                    } else if isNoRemote {
                        error = sync.addJumpOnlyMappings(aliases: sortedChecked, proxyJump: proxyJump)
                    } else {
                        guard let device else { return }
                        error = sync.addMapping(device: device, alias: alias, policy: policy,
                                                forwardTarget: forwardTarget.isEmpty ? nil : forwardTarget,
                                                proxyJump: proxyJump)
                    }
                    if error == nil { dismiss() }
                }
                .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
                .disabled(isNoRemote ? checkedAliases.isEmpty || proxyJump == nil : device == nil || alias.isEmpty)
            }
        }
        .padding(24).frame(width: 520)
        .onAppear {
            if let editing {
                deviceID = Self.noRemoteID
                checkedAliases = Set(editing.aliases)
                proxyJump = editing.proxyJump
                return
            }
            deviceID = sync.devices.first?.keyID ?? Self.noRemoteID
            alias = aliases.first(where: { $0.alias == device?.label })?.alias ?? aliases.first?.alias ?? ""
            selectDefaultForward()
        }
        .onChange(of: deviceID) {
            selectDefaultForward()
            error = nil
        }
    }

    private var confirmTitle: String {
        guard isNoRemote, !checkedAliases.isEmpty else { return editing == nil ? "添加" : "保存" }
        return "\(editing == nil ? "添加" : "保存")（\(checkedAliases.count)）"
    }

    private func toggleChecked(_ alias: String) {
        if checkedAliases.remove(alias) == nil { checkedAliases.insert(alias) }
        error = nil
    }

    /// Multi-select toggles, so the list stays open for picking more.
    private func pickHost(_ picked: String) {
        if isNoRemote { toggleChecked(picked) } else { alias = picked }
    }

    private func pressReturnInHosts(_ matches: [SSHEffectiveHost]) -> Bool {
        if let highlightedHost {
            pickHost(highlightedHost)
            return true
        }
        if hostSearch.isEmpty { return false }
        if matches.count == 1 { pickHost(matches[0].alias) }
        return true
    }

    private var hostPicker: some View {
        let matches = filterSSHHosts(aliases, query: hostSearch)
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("SSH Host").font(.system(size: 12, weight: .medium))
                Text("\(matches.count) / \(aliases.count)").font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
                if isNoRemote {
                    if !checkedAliases.isEmpty {
                        Text("已选 \(checkedAliases.count) 个：\(sortedChecked.joined(separator: "、"))")
                            .font(.system(size: 11, weight: .medium)).foregroundStyle(UITheme.accent)
                            .lineLimit(1).truncationMode(.tail)
                            .help(sortedChecked.joined(separator: "\n"))
                        Button("清空") { checkedAliases = [] }
                            .buttonStyle(.plain).font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                } else if !alias.isEmpty {
                    Text("已选：\(alias)").font(.system(size: 11, weight: .medium))
                        .foregroundStyle(UITheme.accent).lineLimit(1)
                }
            }
            SSHSearchField(placeholder: isNoRemote ? "搜索 Host 名称或地址，↑↓ 选择，⏎ 勾选（可多选）" : "搜索 Host 名称或地址，↑↓ 选择，⏎ 确认",
                           text: $hostSearch, autoFocus: true,
                           onMove: { highlightedHost = movedHighlight(current: highlightedHost, items: matches.map(\.alias), delta: $0) },
                           onReturn: { pressReturnInHosts(matches) })
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(matches) { host in
                            SSHHostRow(title: host.alias, detail: host.display,
                                       selected: isNoRemote ? checkedAliases.contains(host.alias) : alias == host.alias,
                                       highlighted: highlightedHost == host.alias, multiple: isNoRemote) {
                                pickHost(host.alias)
                            }
                            .id(host.alias)
                        }
                        if matches.isEmpty {
                            Text("没有匹配的 Host").font(.system(size: 11)).foregroundStyle(.secondary).padding(24)
                        }
                    }
                }
                .onChange(of: highlightedHost) {
                    if let highlightedHost { proxy.scrollTo(highlightedHost) }
                }
            }
            .frame(height: 150)
            .background(UITheme.panel, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(UITheme.line))
        }
        .onChange(of: hostSearch) { highlightedHost = nil }
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
