import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { AppModel.shared.shutdown() }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            for window in sender.windows where window.canBecomeMain { window.makeKeyAndOrderFront(nil) }
        }
        return true
    }
}

@main
struct IPv6WhitelistApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = AppModel.shared
    @StateObject private var sshSync = SSHSyncModel.shared
    var body: some Scene {
        Window("IPv6 白名单", id: "main") {
            MainView(model: model, sshSync: sshSync)
                .frame(minWidth: 990, minHeight: 760)
        }
        .defaultSize(width: 1120, height: 840)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(after: .appInfo) {
                Button("打开白名单数据目录") { model.openDataFolder() }
            }
        }
        MenuBarExtra {
            StatusMenuView(model: model)
        } label: {
            Image(systemName: model.isEnabled ? "wifi.circle.fill" : "wifi.circle")
        }
    }
}
