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

NGINX_CONFIG_DIR="$TEST_ROOT/nginx"
PANEL_DOMAIN="atlas.example.com"
install -d -m 0755 "$NGINX_CONFIG_DIR"
cat >"$NGINX_CONFIG_DIR/atlas-$PANEL_DOMAIN.conf" <<EOF
# Managed by Nginx Atlas. Manual changes will be replaced.
server { server_name $PANEL_DOMAIN; }
EOF
panel_is_agent_managed

file_help="$(bash "$ROOT_DIR/deploy/install.sh" --help)"
stdin_help="$(bash -s -- --help <"$ROOT_DIR/deploy/install.sh")"
grep -Fq 'Usage:' <<<"$file_help"
grep -Fq 'Usage:' <<<"$stdin_help"

SYSTEMCTL_CALLS=()
systemctl() { SYSTEMCTL_CALLS+=("$*"); }
enable_and_restart_service nginx-atlas-test.service
[[ "${SYSTEMCTL_CALLS[0]}" == "enable nginx-atlas-test.service" ]]
[[ "${SYSTEMCTL_CALLS[1]}" == "restart nginx-atlas-test.service" ]]
unset -f systemctl

printf 'Installer regression checks are valid.\n'
