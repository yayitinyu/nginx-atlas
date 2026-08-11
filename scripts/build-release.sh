#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:?Set VERSION, for example VERSION=0.1.0}"
OUTPUT_DIR="$ROOT_DIR/dist-release"

case "$OUTPUT_DIR" in
  "$ROOT_DIR"/dist-release) ;;
  *) printf 'Unsafe output directory: %s\n' "$OUTPUT_DIR" >&2; exit 1 ;;
esac

rm -rf -- "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

cd "$ROOT_DIR/web"
npm ci
npm run build

cd "$ROOT_DIR"
go test ./...

for arch in amd64 arm64; do
  package_dir="$OUTPUT_DIR/nginx-atlas_${VERSION}_linux_${arch}"
  mkdir -p "$package_dir"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$package_dir/nginx-atlas" ./cmd/atlas
  cp deploy/install.sh "$package_dir/install.sh"
  cp README.md "$package_dir/README.md"
  cp LICENSE "$package_dir/LICENSE"
  tar -C "$OUTPUT_DIR" -czf "$OUTPUT_DIR/nginx-atlas_${VERSION}_linux_${arch}.tar.gz" "$(basename "$package_dir")"
  rm -rf -- "$package_dir"
done

cd "$OUTPUT_DIR"
for archive in ./*.tar.gz; do
  name="$(basename "$archive")"
  digest="$(sha256sum "$archive" | awk '{print $1}')"
  printf '%s  %s\n' "$digest" "$name"
done > checksums.txt
sha256sum --check checksums.txt
printf 'Release assets written to %s\n' "$OUTPUT_DIR"
