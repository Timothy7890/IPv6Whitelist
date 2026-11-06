#!/bin/bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")" && pwd)"
output_dir="${1:-$project_dir/build}"
app_bundle="$output_dir/IPv6 白名单.app"
mkdir -p "$app_bundle/Contents/MacOS" "$app_bundle/Contents/Resources"
cd "$project_dir"
xcrun swiftc -swift-version 5 -O -parse-as-library -target arm64-apple-macosx15.0 \
  Sources/Models.swift Sources/IPv6.swift Sources/CommandRunner.swift Sources/HelperMain.swift \
  -o "$app_bundle/Contents/MacOS/ipv6-route-helper"
xcrun swiftc -swift-version 5 -O -parse-as-library -target arm64-apple-macosx15.0 \
  Sources/Models.swift Sources/IPv6.swift Sources/SSHImporter.swift \
  Sources/SocketClient.swift Sources/CommandRunner.swift Sources/WeChatDiscovery.swift Sources/AppModel.swift \
  Sources/NetbridgeSync.swift Sources/SSHSyncModel.swift Sources/SSHSyncViews.swift Sources/Views.swift Sources/AppEntry.swift \
  -framework AppKit -framework SwiftUI -framework Security \
  -o "$app_bundle/Contents/MacOS/IPv6Whitelist"
cp initial-whitelist.json "$app_bundle/Contents/Resources/initial-whitelist.json"
if [[ -f AppIcon.icns ]]; then cp AppIcon.icns "$app_bundle/Contents/Resources/AppIcon.icns"; fi
cat > "$app_bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>IPv6 白名单</string>
<key>CFBundleDisplayName</key><string>IPv6 白名单</string>
<key>CFBundleIdentifier</key><string>local.timo.IPv6Whitelist</string>
<key>CFBundleExecutable</key><string>IPv6Whitelist</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.2.1</string>
<key>CFBundleVersion</key><string>5</string>
<key>LSMinimumSystemVersion</key><string>15.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>NSHumanReadableCopyright</key><string>Local utility. No analytics.</string>
</dict></plist>
PLIST
/usr/bin/codesign --force --sign - "$app_bundle/Contents/MacOS/ipv6-route-helper"
/usr/bin/codesign --force --sign - "$app_bundle"
/usr/bin/codesign --verify --deep --strict "$app_bundle"
printf 'Built: %s\n' "$app_bundle"
