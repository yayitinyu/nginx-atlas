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
cp "$ROOT_DIR/deploy/install.sh" "$OUTPUT_DIR/install.sh"
chmod 0755 "$OUTPUT_DIR/install.sh"

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
  chmod 0755 "$package_dir/nginx-atlas" "$package_dir/install.sh"
  chmod 0644 "$package_dir/README.md" "$package_dir/LICENSE"

  package_name="$(basename "$package_dir")"
  tar_path="$OUTPUT_DIR/nginx-atlas_${VERSION}_linux_${arch}.tar"
  archive="${tar_path}.gz"
  tar --owner=0 --group=0 --numeric-owner --mode=0755 --no-recursion \
    -C "$OUTPUT_DIR" -cf "$tar_path" "$package_name"
  tar --owner=0 --group=0 --numeric-owner --mode=0755 \
    -C "$OUTPUT_DIR" -rf "$tar_path" "$package_name/nginx-atlas" "$package_name/install.sh"
  tar --owner=0 --group=0 --numeric-owner --mode=0644 \
    -C "$OUTPUT_DIR" -rf "$tar_path" "$package_name/README.md" "$package_name/LICENSE"
  gzip -9 "$tar_path"
  tar -tvzf "$archive" | awk '
    $NF ~ /\/nginx-atlas$/ { binary = 1; if ($1 !~ /^-rwx/) exit 1 }
    $NF ~ /\/install\.sh$/ { installer = 1; if ($1 !~ /^-rwx/) exit 1 }
    END { if (!binary || !installer) exit 1 }
  '
  rm -rf -- "$package_dir"
done

cd "$OUTPUT_DIR"
for asset in ./*.tar.gz ./install.sh; do
  name="$(basename "$asset")"
  digest="$(sha256sum "$asset" | awk '{print $1}')"
  printf '%s  %s\n' "$digest" "$name"
done > checksums.txt
sha256sum --check checksums.txt
printf 'Release assets written to %s\n' "$OUTPUT_DIR"
