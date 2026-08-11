#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-dev}"

cd "$ROOT_DIR/web"
npm ci
npm run build

cd "$ROOT_DIR"
mkdir -p bin
go test ./...
go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o bin/nginx-atlas ./cmd/atlas

printf 'Built %s/bin/nginx-atlas (%s)\n' "$ROOT_DIR" "$VERSION"
