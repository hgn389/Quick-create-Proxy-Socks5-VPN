#!/usr/bin/env bash
set -Eeuo pipefail

readonly version='0.9.9.0'
readonly fingerprint='FC12214499FCC7BA1CFF6CDC0312384E3A73940B'
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(dirname "$script_dir")"
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

for program in curl gpg sha256sum dpkg-deb rpm2cpio cpio; do
  command -v "$program" >/dev/null 2>&1 || { echo "Missing build tool: $program" >&2; exit 1; }
done

download_asset() {
  local filename="$1"
  curl -fsSL --retry 3 \
    "https://github.com/3proxy/3proxy/releases/download/$version/$filename" \
    -o "$work_dir/$filename"
}

curl -fsSL --retry 3 \
  "https://raw.githubusercontent.com/3proxy/3proxy/$version/3proxy-release-key.asc" \
  -o "$work_dir/3proxy-release-key.asc"
actual_fingerprint="$(gpg --show-keys --with-colons "$work_dir/3proxy-release-key.asc" 2>/dev/null | awk -F: '$1=="fpr" {print $10; exit}')"
[[ "$actual_fingerprint" == "$fingerprint" ]] || { echo "3proxy signing key fingerprint mismatch" >&2; exit 1; }
mkdir -m 0700 "$work_dir/gnupg"
export GNUPGHOME="$work_dir/gnupg"
gpg --batch --quiet --import "$work_dir/3proxy-release-key.asc"

for upstream_arch in x86_64 arm64; do
  download_asset "SHA256SUMS-$upstream_arch"
  download_asset "SHA256SUMS-$upstream_arch.asc"
  gpg --batch --verify \
    "$work_dir/SHA256SUMS-$upstream_arch.asc" \
    "$work_dir/SHA256SUMS-$upstream_arch" >/dev/null 2>&1 || {
      echo "3proxy checksum signature verification failed for $upstream_arch" >&2
      exit 1
    }
done

verify_asset() {
  local filename="$1" upstream_arch="$2" expected
  expected="$(awk -v name="$filename" '$2==name || $2=="*"name {print $1; exit}' "$work_dir/SHA256SUMS-$upstream_arch")"
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Missing signed checksum for $filename" >&2; exit 1; }
  printf '%s  %s\n' "$expected" "$work_dir/$filename" | sha256sum -c - >/dev/null
}

mkdir -p "$project_dir/dist/vendor/3proxy"
for go_arch in amd64 arm64; do
  if [[ "$go_arch" == amd64 ]]; then
    upstream_arch='x86_64'
    deb_name="3proxy-$version.x86_64.deb"
    rpm_arch='x86_64'
  else
    upstream_arch='arm64'
    deb_name="3proxy-$version.arm64.deb"
    rpm_arch='aarch64'
  fi
  download_asset "$deb_name"
  verify_asset "$deb_name" "$upstream_arch"
  extract_dir="$work_dir/deb-$go_arch"
  mkdir -p "$extract_dir"
  dpkg-deb -x "$work_dir/$deb_name" "$extract_dir"
  [[ -x "$extract_dir/bin/3proxy" ]] || { echo "3proxy executable missing from $deb_name" >&2; exit 1; }
  target_dir="$project_dir/dist/vendor/3proxy/deb/$go_arch"
  mkdir -p "$target_dir"
  install -m 0755 "$extract_dir/bin/3proxy" "$target_dir/3proxy"

  for el_major in 8 9 10; do
      rpm_name="3proxy-$version.el$el_major.$rpm_arch.rpm"
      download_asset "$rpm_name"
      verify_asset "$rpm_name" "$upstream_arch"
      extract_dir="$work_dir/el$el_major-$go_arch"
      mkdir -p "$extract_dir"
      (
        cd "$extract_dir"
        rpm2cpio "$work_dir/$rpm_name" | cpio -idm --quiet './usr/bin/3proxy' './bin/3proxy' 2>/dev/null
      )
      binary="$(find "$extract_dir" -type f -name 3proxy -print -quit)"
      [[ -n "$binary" && -x "$binary" ]] || { echo "3proxy executable missing from $rpm_name" >&2; exit 1; }
      target_dir="$project_dir/dist/vendor/3proxy/el$el_major/$go_arch"
      mkdir -p "$target_dir"
      install -m 0755 "$binary" "$target_dir/3proxy"
  done
done

cp "$project_dir/third_party/3proxy-LICENSE" "$project_dir/dist/vendor/3proxy/LICENSE"
(
  cd "$project_dir/dist/vendor/3proxy"
  manifest_temp="$(mktemp)"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > "$manifest_temp"
  mv "$manifest_temp" SHA256SUMS
)
echo "Verified 3proxy binaries are in dist/vendor/3proxy/."
