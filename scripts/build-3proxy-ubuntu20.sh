#!/usr/bin/env bash
set -Eeuo pipefail
# Reproducible, static 3proxy build for Ubuntu 20.04 and other older glibc systems.
# Build on a workstation. Zig 0.13.0 must be available as `zig`.
readonly SOURCE_COMMIT='da99424eac4092e3722f1a5b1844cfe80478f580'
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(dirname "$script_dir")"
for cmd in git zig make sha256sum; do command -v "$cmd" >/dev/null || { echo "Missing build tool: $cmd" >&2; exit 1; }; done
[[ "$(zig version)" == '0.13.0' ]] || { echo 'Zig 0.13.0 is required.' >&2; exit 1; }
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
for arch in amd64 arm64; do
  if [[ "$arch" == amd64 ]]; then target='x86_64-linux-musl'; else target='aarch64-linux-musl'; fi
  source_dir="$work_dir/source-$arch"
  git clone -q --depth 1 --branch 0.9.9.0 https://github.com/3proxy/3proxy.git "$source_dir"
  [[ "$(git -C "$source_dir" rev-parse HEAD)" == "$SOURCE_COMMIT" ]] || { echo 'Unexpected 3proxy source commit.' >&2; exit 1; }
  make -s -C "$source_dir" -f Makefile.Linux \
    CC="zig cc -target $target" LN="zig cc -target $target" \
    EXTRA_CFLAGS=-DNOPLUGINS EXTRA_LDFLAGS=-static \
    OPENSSL_CHECK=false WOLFSSL_CHECK=false PCRE_CHECK=false PAM_CHECK=false
  target_dir="$project_dir/dist/vendor/3proxy/ubuntu20/$arch"
  mkdir -p "$target_dir"
  install -m 0755 "$source_dir/bin/3proxy" "$target_dir/3proxy"
done
(
  cd "$project_dir/dist/vendor/3proxy"
  manifest_temp="$(mktemp)"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > "$manifest_temp"
  mv "$manifest_temp" SHA256SUMS
)
echo 'Static Ubuntu 20.04 3proxy binaries are ready.'
