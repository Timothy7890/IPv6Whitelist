#!/bin/bash
# Builds the app from the private whitelist branch and zips it for copying to
# your own Macs. The zip contains the private whitelist: never publish it.
#
#   bash ./package.sh [output-dir]     (output-dir defaults to ~/Documents)
#
# It builds from a temporary checkout of the private branch, so it runs from any
# branch and leaves your working tree alone. PRIVATE_BRANCH overrides the branch.
set -euo pipefail
project_dir="$(cd "$(dirname "$0")" && pwd)"
private_branch="${PRIVATE_BRANCH:-chore/update-initial-whitelist}"
cd "$project_dir"

if [[ -t 1 ]]; then
  bold=$'\e[1m' dim=$'\e[2m' red=$'\e[31m' green=$'\e[32m' yellow=$'\e[33m' cyan=$'\e[36m' reset=$'\e[0m'
else
  bold='' dim='' red='' green='' yellow='' cyan='' reset=''
fi
total_steps=5
step_no=0
started=$SECONDS

step() { step_no=$((step_no + 1)); printf '%s[%d/%d]%s %s … ' "$cyan" "$step_no" "$total_steps" "$reset" "$1"; }
ok() { printf '%s✓%s %s\n' "$green" "$reset" "${1:-}"; }
fail() { printf '\n%s✗ 打包中止：%s%s\n' "$red" "$1" "$reset" >&2; exit 1; }
# Labels are padded by hand: printf counts bytes, not the width of CJK text.
row() { printf '  %s%s%s %s\n' "$dim" "$1" "$reset" "$2"; }

# Shows a spinner with elapsed seconds while a slow command runs.
run_with_spinner() {
  local log="$1"; shift
  "$@" >"$log" 2>&1 &
  local pid=$! begin=$SECONDS frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
  if [[ -t 1 ]]; then
    printf '\e7'
    while kill -0 "$pid" 2>/dev/null; do
      printf '\e8%s%s %ds%s' "$dim" "${frames:i++%10:1}" $((SECONDS - begin)) "$reset"
      sleep 0.1
    done
    printf '\e8\e[K'
  fi
  wait "$pid"
}

printf '\n%s📦 IPv6 白名单 · 私有打包%s\n\n' "$bold" "$reset"

step "检查私有分支"
git rev-parse --verify --quiet "refs/heads/${private_branch}" >/dev/null ||
  fail "找不到本地分支 ${private_branch}。"
git merge-base --is-ancestor main "$private_branch" ||
  fail "${private_branch} 还没包含 main 的最新代码，请先运行：git switch ${private_branch} && git rebase main"
if git rev-parse --abbrev-ref --symbolic-full-name "${private_branch}@{u}" >/dev/null 2>&1; then
  fail "${private_branch} 设置了远端上游，它不应该被推送。请检查后用 git branch --unset-upstream ${private_branch} 取消。"
fi
ahead="$(git rev-list --count "main..${private_branch}")"
ok "${private_branch}（已包含 main，比 main 多 ${ahead} 个本地提交，无上游）"

output_dir="${1:-$HOME/Documents}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
case "$output_dir" in
  "$project_dir"/build|"$project_dir"/build/*) ;;
  "$project_dir"|"$project_dir"/*) fail "输出目录在项目里但不在已忽略的 build/ 下，私有白名单可能被提交。" ;;
esac

work="$(mktemp -d)"
cleanup() {
  local status=$?
  git -C "$project_dir" worktree remove --force "$work/src" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

step "检出到临时目录"
git worktree add --quiet --detach "$work/src" "$private_branch"
commit="$(git -C "$work/src" rev-parse --short HEAD)"
subject="$(git -C "$work/src" log -1 --format=%s)"
ok "$commit"

step "编译 App"
build_began=$SECONDS
if ! run_with_spinner "$work/build.log" bash "$work/src/build.sh" "$work/out"; then
  printf '\n'
  cat "$work/build.log" >&2
  fail "编译失败，日志见上方。"
fi
ok "用时 $((SECONDS - build_began))s"

app="$work/out/IPv6 白名单.app"
step "校验签名"
/usr/bin/codesign --verify --deep --strict "$app" 2>"$work/codesign.log" ||
  { cat "$work/codesign.log" >&2; fail "签名校验失败。"; }
ok "ad-hoc 签名有效"

plist="$app/Contents/Info.plist"
version="$(plutil -extract CFBundleShortVersionString raw "$plist")"
build_no="$(plutil -extract CFBundleVersion raw "$plist")"
min_os="$(plutil -extract LSMinimumSystemVersion raw "$plist")"
archs="$(lipo -archs "$app/Contents/MacOS/IPv6Whitelist")"
seed="$app/Contents/Resources/initial-whitelist.json"
entries="$(grep -c '"address"' "$seed" || true)"
enabled="$(grep -c '"enabled" : true' "$seed" || true)"
zip="$output_dir/IPv6Whitelist-${version}-$(date +%Y%m%d)-${commit}.zip"

step "压缩为 zip"
rm -f "$zip"
# ditto keeps the code signature intact, unlike zip.
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"
ok "$(du -h "$zip" | cut -f1 | tr -d ' ')"

printf '\n%s%s✅ 打包完成%s %s（共 %ds）%s\n\n' "$bold" "$green" "$reset" "$dim" $((SECONDS - started)) "$reset"
row "文件    " "${zip/#$HOME/~}"
row "版本    " "${version}（build ${build_no}）"
row "提交    " "$commit  $subject"
row "白名单  " "$entries 条（默认启用 $enabled 条）"
row "适用    " "$archs · macOS $min_os 及以上"
row "SHA-256 " "$(shasum -a 256 "$zip" | cut -c1-16)…"

cat <<EOF

${bold}在另一台 Mac 上：${reset}
  1. 先退出旧版：菜单栏图标 → 退出 Wi-Fi 出口管理（只关窗口不算退出）
  2. 双击 zip 解压，把「IPv6 白名单.app」拖进「应用程序」，选择替换
  3. 如果打不开：系统设置 → 隐私与安全性 → 仍要打开
  4. 打开后点「开启管理」并授权；钥匙串弹窗选「始终允许」
  ${dim}原有白名单和 SSH 配置保存在 ~/Library/Application Support/IPv6Whitelist，不受影响。${reset}

${yellow}⚠ 这个文件包含私有白名单，只通过 AirDrop、iCloud Drive 或 scp 拷到自己的 Mac。${reset}

EOF
