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

fail() { printf '打包中止：%s\n' "$1" >&2; exit 1; }

git rev-parse --verify --quiet "refs/heads/${private_branch}" >/dev/null ||
  fail "找不到本地分支 ${private_branch}。"
git merge-base --is-ancestor main "$private_branch" ||
  fail "${private_branch} 还没包含 main 的最新代码，请先运行：git switch ${private_branch} && git rebase main"
if git rev-parse --abbrev-ref --symbolic-full-name "${private_branch}@{u}" >/dev/null 2>&1; then
  fail "${private_branch} 设置了远端上游，它不应该被推送。请检查后用 git branch --unset-upstream ${private_branch} 取消。"
fi

output_dir="${1:-$HOME/Documents}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
case "$output_dir" in
  "$project_dir"/build|"$project_dir"/build/*) ;;
  "$project_dir"|"$project_dir"/*) fail "输出目录在项目里但不在已忽略的 build/ 下，私有白名单可能被提交。" ;;
esac

work="$(mktemp -d)"
cleanup() {
  git -C "$project_dir" worktree remove --force "$work/src" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
git worktree add --quiet --detach "$work/src" "$private_branch"
commit="$(git -C "$work/src" rev-parse --short HEAD)"

if ! bash "$work/src/build.sh" "$work/out" >"$work/build.log" 2>&1; then
  cat "$work/build.log" >&2
  fail "编译失败。"
fi
app="$work/out/IPv6 白名单.app"
/usr/bin/codesign --verify --deep --strict "$app"

version="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")"
entries="$(grep -c '"address"' "$app/Contents/Resources/initial-whitelist.json" || true)"
zip="$output_dir/IPv6Whitelist-${version}-$(date +%Y%m%d)-${commit}.zip"
rm -f "$zip"
# ditto keeps the code signature intact, unlike zip.
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"

printf '已打包：%s\n' "$zip"
printf '版本 %s，提交 %s，内置白名单 %s 条，大小 %s\n' "$version" "$commit" "$entries" "$(du -h "$zip" | cut -f1)"
printf '这个文件包含私有白名单，只通过 AirDrop、iCloud Drive 或 scp 拷到自己的 Mac。\n'
