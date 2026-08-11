#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../deploy/install.sh
source "$ROOT_DIR/deploy/install.sh"

TEST_ROOT="$(mktemp -d)"
cleanup() { rm -rf -- "$TEST_ROOT"; }
trap cleanup EXIT

STATE_ROOT="$TEST_ROOT/state"
install -d -m 0700 "$STATE_ROOT" "$STATE_ROOT/agent"
prepare_server_state_directory root root

[[ "$(stat -c '%a' "$STATE_ROOT")" == "710" ]]
[[ "$(stat -c '%U:%G' "$STATE_ROOT")" == "root:root" ]]
[[ "$(stat -c '%a' "$STATE_ROOT/server")" == "700" ]]
[[ "$(stat -c '%U:%G' "$STATE_ROOT/server")" == "root:root" ]]

printf 'Installer state-directory permissions are valid.\n'
