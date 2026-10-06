#!/usr/bin/env bash
set -Eeuo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(dirname "$script_dir")"
version="$(cat "$project_dir/VERSION")"
release_name="qcp-v$version"
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
for file in \
  dist/go/qcp-linux-amd64 dist/go/qcp-linux-arm64 dist/go/SHA256SUMS \
  dist/vendor/3proxy/SHA256SUMS \
  dist/vendor/3proxy/ubuntu20/amd64/3proxy dist/vendor/3proxy/ubuntu20/arm64/3proxy; do
  [[ -f "$project_dir/$file" ]] || { echo "Missing $file" >&2; exit 1; }
done
(cd "$project_dir/dist/go" && sha256sum -c SHA256SUMS)
(cd "$project_dir/dist/vendor/3proxy" && sha256sum -c SHA256SUMS)
mkdir -p "$work_dir/$release_name"
for path in README.md VERSION install.sh docs systemd; do
  cp -a "$project_dir/$path" "$work_dir/$release_name/"
done
# Copy verified runtime payloads into the release layout.
mkdir -p "$work_dir/$release_name/dist/vendor" "$work_dir/$release_name/dist/go"
cp -a "$project_dir/dist/go/." "$work_dir/$release_name/dist/go/"
cp -a "$project_dir/dist/vendor/3proxy" "$work_dir/$release_name/dist/vendor/"
mkdir -p "$project_dir/dist/release"
tar -C "$work_dir" -czf "$project_dir/dist/release/$release_name-linux-amd64-arm64.tar.gz" "$release_name"
(cd "$project_dir/dist/release" && sha256sum "$release_name-linux-amd64-arm64.tar.gz" > SHA256SUMS)
echo "Release: $project_dir/dist/release/$release_name-linux-amd64-arm64.tar.gz"
