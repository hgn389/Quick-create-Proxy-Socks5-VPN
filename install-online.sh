#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly QCP_VERSION="1.0.0-beta.1"
readonly QCP_REPOSITORY="hgn389/Quick-create-Proxy-Socks5-VPN"
readonly QCP_ARCHIVE="qcp-v${QCP_VERSION}-linux-amd64-arm64.tar.gz"
readonly QCP_RELEASE_URL="https://github.com/${QCP_REPOSITORY}/releases/download/v${QCP_VERSION}"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "Run this installer as root, for example: curl ... | sudo bash"

for command_name in curl tar sha256sum awk mktemp; do
  command -v "$command_name" >/dev/null 2>&1 || fail "Required command is missing: $command_name"
done

download_dir="$(mktemp -d -t qcp-install.XXXXXXXX)"
cleanup() {
  rm -rf -- "$download_dir"
}
trap cleanup EXIT

curl_args=(
  --proto '=https'
  --tlsv1.2
  --fail
  --location
  --silent
  --show-error
  --retry 3
)

printf 'Downloading QCP v%s from GitHub Release...\n' "$QCP_VERSION"
curl "${curl_args[@]}" "$QCP_RELEASE_URL/$QCP_ARCHIVE" -o "$download_dir/$QCP_ARCHIVE"
curl "${curl_args[@]}" "$QCP_RELEASE_URL/SHA256SUMS" -o "$download_dir/SHA256SUMS"

expected_hash="$(awk -v name="$QCP_ARCHIVE" '$2 == name { print $1; exit }' "$download_dir/SHA256SUMS")"
[[ "$expected_hash" =~ ^[0-9a-fA-F]{64}$ ]] || fail "Release checksum does not contain $QCP_ARCHIVE"
printf '%s  %s\n' "$expected_hash" "$download_dir/$QCP_ARCHIVE" | sha256sum -c -

tar -xzf "$download_dir/$QCP_ARCHIVE" -C "$download_dir"
bundled_installer="$download_dir/qcp-v${QCP_VERSION}/install.sh"
[[ -x "$bundled_installer" ]] || fail "The verified release does not contain an executable installer"

if { exec 3</dev/tty; } 2>/dev/null; then
  "$bundled_installer" --install <&3
  exec 3<&-
else
  fail "An interactive terminal is required. Download the release and run install.sh manually for unattended installation."
fi
