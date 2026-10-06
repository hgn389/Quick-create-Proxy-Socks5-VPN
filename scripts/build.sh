#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(dirname "$script_dir")"
cd "$project_dir"

command -v go >/dev/null 2>&1 || { echo "Go compiler is required on the build machine." >&2; exit 1; }
mkdir -p dist/go
for target_arch in amd64 arm64; do
  echo "Building qcp for linux/$target_arch"
  GOOS=linux GOARCH="$target_arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w -buildid=' \
    -o "dist/go/qcp-linux-$target_arch" ./cmd/qcp
done
(
  cd dist/go
  sha256sum qcp-linux-amd64 qcp-linux-arm64 > SHA256SUMS
)
echo "Go binaries and checksums are in dist/go/."
