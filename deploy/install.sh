#!/usr/bin/env bash
set -Eeuo pipefail

PROGRAM="nginx-atlas"
DEFAULT_REPOSITORY="yayitinyu/nginx-atlas"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nginx-atlas"
STATE_ROOT="/var/lib/nginx-atlas"
SYSTEMD_DIR="/etc/systemd/system"
NGINX_CONFIG_DIR="/etc/nginx/conf.d"
NGINX_PANEL_CONFIG="$NGINX_CONFIG_DIR/nginx-atlas-panel.conf"
PROXY_HEADER_CONFIG="$CONFIG_DIR/proxy-token.conf"
CONTROLLER_ADDR="127.0.0.1:909"
CONTROLLER_URL="http://$CONTROLLER_ADDR"

MODE=""
SERVER_URL=""
PUBLIC_URL=""
PANEL_DOMAIN=""
NODE_NAME="$(hostname 2>/dev/null || printf 'nginx-node')"
ENROLLMENT_TOKEN=""
BINARY_FILE=""
BINARY_URL="${ATLAS_BINARY_URL:-}"
BINARY_SHA256="${ATLAS_BINARY_SHA256:-}"
REPOSITORY="${ATLAS_REPO:-$DEFAULT_REPOSITORY}"
SKIP_LEGO="false"
PURGE_STATE="false"
FORCE_LOCAL="false"
TOKEN_STDIN="false"
ADMIN_TOKEN_CREATED="false"
LOCAL_TOKEN=""
PROXY_TOKEN=""
BACKUP_DIR=""
WORK_DIR=""

log() { printf '\033[1;32m[atlas]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[atlas]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[atlas]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  install.sh server --public-url https://atlas.example.com [--panel-domain atlas.example.com]
  printf '%s' TOKEN | install.sh agent --server https://atlas.example.com --token-stdin [--name Tokyo-02]
  install.sh uninstall-agent [--force-local]
  install.sh uninstall-server

Options:
  --binary-file PATH       Install a locally built nginx-atlas binary.
  --binary-url URL         Download a binary or tar.gz from a custom URL.
  --binary-sha256 SHA256   Required with --binary-url.
  --repo OWNER/REPO        GitHub repository used for the latest release.
  --skip-lego              Do not install the lego DNS-01 client.
  --purge-state            With uninstall-server: also remove /var/lib/nginx-atlas
                           and /etc/nginx-atlas (irreversible).
  --force-local            With uninstall-agent: remove local state even when the
                           controller was already revoked or is unavailable.
  --token-stdin            Read the one-time enrollment token from standard input.

The server mode also installs a local node agent. Existing state, secrets, and
service configuration are preserved on reruns.

uninstall-server stops the controller and local agent, removes systemd units,
the shared binary, installer-managed panel nginx config, and optionally state.
It never removes Nginx packages, user site configs, or /etc/ssl certificates.
EOF
}

cleanup() {
  case "$WORK_DIR" in
    /tmp/nginx-atlas.*) [[ -d "$WORK_DIR" ]] && rm -rf -- "$WORK_DIR" ;;
    "") ;;
    *) warn "拒绝清理异常临时目录：$WORK_DIR" ;;
  esac
}
trap cleanup EXIT

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "请使用 root 或 sudo 运行安装器。"
}

parse_args() {
  [[ $# -gt 0 ]] || { usage; exit 2; }
  MODE="$1"
  shift
  case "$MODE" in
    server|agent|uninstall-agent|uninstall-server) ;;
    -h|--help|help) usage; exit 0 ;;
    *) die "未知安装模式：$MODE" ;;
  esac
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server) [[ $# -ge 2 ]] || die "--server 缺少参数"; SERVER_URL="$2"; shift 2 ;;
      --public-url) [[ $# -ge 2 ]] || die "--public-url 缺少参数"; PUBLIC_URL="$2"; shift 2 ;;
      --panel-domain) [[ $# -ge 2 ]] || die "--panel-domain 缺少参数"; PANEL_DOMAIN="$2"; shift 2 ;;
      --token-stdin) TOKEN_STDIN="true"; shift ;;
      --name) [[ $# -ge 2 ]] || die "--name 缺少参数"; NODE_NAME="$2"; shift 2 ;;
      --binary-file) [[ $# -ge 2 ]] || die "--binary-file 缺少参数"; BINARY_FILE="$2"; shift 2 ;;
      --binary-url) [[ $# -ge 2 ]] || die "--binary-url 缺少参数"; BINARY_URL="$2"; shift 2 ;;
      --binary-sha256) [[ $# -ge 2 ]] || die "--binary-sha256 缺少参数"; BINARY_SHA256="$2"; shift 2 ;;
      --repo) [[ $# -ge 2 ]] || die "--repo 缺少参数"; REPOSITORY="$2"; shift 2 ;;
      --skip-lego) SKIP_LEGO="true"; shift ;;
      --purge-state) PURGE_STATE="true"; shift ;;
      --force-local) FORCE_LOCAL="true"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "未知参数：$1" ;;
    esac
  done
}

validate_args() {
  if [[ "$MODE" == "uninstall-agent" || "$MODE" == "uninstall-server" ]]; then
    if [[ "$PURGE_STATE" == "true" && "$MODE" != "uninstall-server" ]]; then
      die "--purge-state 仅可与 uninstall-server 一起使用。"
    fi
    if [[ "$FORCE_LOCAL" == "true" && "$MODE" != "uninstall-agent" ]]; then
      die "--force-local 仅可与 uninstall-agent 一起使用。"
    fi
    return
  fi
  [[ "$FORCE_LOCAL" == "false" ]] || die "--force-local 仅可与 uninstall-agent 一起使用。"
  if [[ "$PURGE_STATE" == "true" ]]; then
    die "--purge-state 仅可与 uninstall-server 一起使用。"
  fi
  [[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "GitHub 仓库必须使用 OWNER/REPO 格式。"
  [[ "$NODE_NAME" =~ ^[^[:cntrl:]]{2,64}$ ]] || die "节点名称必须为 2–64 个可见字符。"
  if [[ "$MODE" == "agent" ]]; then
    [[ "$SERVER_URL" =~ ^https://[^/[:space:]]+ ]] || die "远程主控地址必须使用 HTTPS。"
    [[ ${#ENROLLMENT_TOKEN} -ge 24 ]] || die "需要面板生成的一次性添加令牌。"
  else
    [[ "$PUBLIC_URL" =~ ^https://[^/[:space:]]+ ]] || die "server 模式需要 --public-url https://atlas.example.com。"
    if [[ -z "$PANEL_DOMAIN" ]]; then
      PANEL_DOMAIN="${PUBLIC_URL#https://}"
      PANEL_DOMAIN="${PANEL_DOMAIN%%/*}"
      PANEL_DOMAIN="${PANEL_DOMAIN%%:*}"
    fi
    [[ "$PANEL_DOMAIN" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{1,251}[A-Za-z0-9]$ ]] || die "面板域名无效。"
  fi
  if [[ -n "$BINARY_URL" ]]; then
    [[ "$BINARY_URL" =~ ^https:// ]] || die "自定义二进制 URL 必须使用 HTTPS。"
    [[ "$BINARY_SHA256" =~ ^[A-Fa-f0-9]{64}$ ]] || die "--binary-url 必须同时提供 64 位 --binary-sha256。"
  fi
  if [[ -n "$BINARY_FILE" ]]; then
    [[ -f "$BINARY_FILE" ]] || die "本地二进制不存在：$BINARY_FILE"
  fi
}

read_enrollment_token() {
  if [[ "$TOKEN_STDIN" == "true" ]]; then
    IFS= read -r ENROLLMENT_TOKEN || [[ -n "$ENROLLMENT_TOKEN" ]] || die "无法从标准输入读取添加令牌。"
  fi
}

preserve_takeover_backups() {
  if [[ -d "$STATE_ROOT/agent/takeovers" ]] && find "$STATE_ROOT/agent/takeovers" -mindepth 1 -print -quit | grep -q .; then
    local takeover_backup="/var/backups/nginx-atlas/agent-takeovers-$(date -u +%Y%m%dT%H%M%SZ)"
    install -d -m 0700 "$(dirname "$takeover_backup")"
    mv -- "$STATE_ROOT/agent/takeovers" "$takeover_backup"
    warn "接管规则的原始备份已保留在 $takeover_backup；卸载不会破坏恢复能力。"
  fi
}

uninstall_agent_mode() {
  log "停止并移除 Nginx Atlas 节点代理"
  systemctl disable --now nginx-atlas-agent.service >/dev/null 2>&1 || true
  if ! unregister_agent_from_controller; then
    if [[ "$FORCE_LOCAL" != "true" ]]; then
      systemctl enable --now nginx-atlas-agent.service >/dev/null 2>&1 || true
      die "主控未确认撤销节点；已保留本地凭据并尝试恢复代理。确认已在面板移除后可使用 --force-local。"
    fi
    warn "主控未确认撤销节点；按 --force-local 仅清理本机代理。"
  fi
  preserve_takeover_backups
  rm -f -- "$SYSTEMD_DIR/nginx-atlas-agent.service" "$CONFIG_DIR/agent.env"
  case "$STATE_ROOT/agent" in
    /var/lib/nginx-atlas/agent) rm -rf -- "$STATE_ROOT/agent" ;;
    *) die "拒绝清理异常代理目录：$STATE_ROOT/agent" ;;
  esac
  if [[ ! -f "$SYSTEMD_DIR/nginx-atlas-server.service" ]]; then
    rm -f -- "$INSTALL_DIR/$PROGRAM"
  else
    log "检测到本机主控服务，已保留共享二进制与主控数据。"
  fi
  systemctl daemon-reload
  log "节点代理已卸载；Nginx 配置、软件包及 /etc/ssl 证书均未修改。"
}

read_agent_env_value() {
  local key="$1" file="$CONFIG_DIR/agent.env"
  [[ -r "$file" ]] || return 0
  awk -v prefix="$key=" 'index($0, prefix) == 1 { print substr($0, length(prefix) + 1); exit }' "$file"
}

unregister_agent_from_controller() {
  local state_path server_url ca_cert
  state_path="$(read_agent_env_value ATLAS_AGENT_STATE_PATH)"
  server_url="$(read_agent_env_value ATLAS_SERVER_URL)"
  ca_cert="$(read_agent_env_value ATLAS_CA_CERT)"
  [[ -n "$state_path" ]] || state_path="$STATE_ROOT/agent/state.json"
  if [[ ! -s "$state_path" ]]; then
    if [[ -f "$CONFIG_DIR/agent.env" ]]; then
      warn "节点配置仍存在，但本地凭据状态缺失，无法证明主控已撤销。"
      return 1
    fi
    return 0
  fi
  if [[ ! -x "$INSTALL_DIR/$PROGRAM" || -z "$server_url" ]]; then
    warn "存在节点凭据，但缺少注销所需的二进制或主控地址。"
    return 1
  fi
  if [[ "$server_url" == "http://127.0.0.1:9090" ]]; then
    server_url="$CONTROLLER_URL"
    warn "旧版本机主控端口不具备进程身份保护；仅尝试通过受保护端口 $CONTROLLER_URL 注销。"
  fi
  local args=(unregister-agent --server "$server_url" --state "$state_path")
  [[ -n "$ca_cert" ]] && args+=(--ca-cert "$ca_cert")
  if "$INSTALL_DIR/$PROGRAM" "${args[@]}"; then
    log "主控中的节点记录已移除。"
    return 0
  else
    return 1
  fi
}

uninstall_server_mode() {
  log "停止并移除 Nginx Atlas 主控与本机节点代理"
  systemctl disable --now nginx-atlas-agent.service >/dev/null 2>&1 || true
  systemctl disable --now nginx-atlas-server.service >/dev/null 2>&1 || true
  rm -f -- \
    "$SYSTEMD_DIR/nginx-atlas-agent.service" \
    "$SYSTEMD_DIR/nginx-atlas-server.service"
  if [[ -f "$NGINX_PANEL_CONFIG" ]] && grep -Fq 'Managed by the Nginx Atlas installer.' "$NGINX_PANEL_CONFIG"; then
    rm -f -- "$NGINX_PANEL_CONFIG"
    if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
      systemctl reload nginx >/dev/null 2>&1 || true
      log "已移除安装器创建的面板 Nginx 站点配置并重载 Nginx。"
    else
      warn "已移除面板 Nginx 配置，但 nginx -t/reload 未成功；请手动检查 Nginx。"
    fi
  fi
  rm -f -- "$INSTALL_DIR/$PROGRAM"
  if [[ "$PURGE_STATE" == "true" ]]; then
    preserve_takeover_backups
    case "$CONFIG_DIR" in
      /etc/nginx-atlas) rm -rf -- "$CONFIG_DIR" ;;
      *) die "拒绝清理异常配置目录：$CONFIG_DIR" ;;
    esac
    case "$STATE_ROOT" in
      /var/lib/nginx-atlas) rm -rf -- "$STATE_ROOT" ;;
      *) die "拒绝清理异常状态目录：$STATE_ROOT" ;;
    esac
    if id nginx-atlas >/dev/null 2>&1; then
      userdel nginx-atlas >/dev/null 2>&1 || warn "无法删除系统用户 nginx-atlas，可稍后手动处理。"
    fi
    log "已清除配置、状态与主密钥（--purge-state）。"
  else
    log "已保留 $CONFIG_DIR 与 $STATE_ROOT；重新安装可恢复同一主密钥与状态。"
    log "若需彻底删除，请追加 --purge-state。"
  fi
  systemctl daemon-reload
  log "主控已卸载；Nginx 软件包、托管站点配置 atlas-*.conf 与 /etc/ssl 证书均未修改。"
}

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
  else
    die "仅支持 apt、dnf 或 yum 系列 Linux。"
  fi
}

install_packages() {
  local packages=(curl ca-certificates jq tar gzip openssl)
  if ! command -v nginx >/dev/null 2>&1; then
    packages+=(nginx)
  fi
  log "检查系统依赖与 Nginx"
  case "$PKG_MANAGER" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y --no-install-recommends "${packages[@]}"
      ;;
    dnf) dnf install -y "${packages[@]}" ;;
    yum) yum install -y "${packages[@]}" ;;
  esac
  command -v nginx >/dev/null 2>&1 || die "Nginx 安装失败。"
  systemctl enable --now nginx
}

map_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) die "暂不支持的 CPU 架构：$(uname -m)" ;;
  esac
}

verify_sha256() {
  local file="$1" expected="$2" actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  [[ "${actual,,}" == "${expected,,}" ]] || die "SHA-256 校验失败：$(basename "$file")"
}

checksum_from_manifest() {
  local manifest="$1" wanted="$2"
  awk -v wanted="$wanted" '
    {
      name = $2
      sub(/^\*/, "", name)
      sub(/^\.\//, "", name)
      if (name == wanted) {
        print $1
        exit
      }
    }
  ' "$manifest"
}

install_binary() {
  local destination="$INSTALL_DIR/$PROGRAM" archive asset_url checksum_url expected release_json arch
  if [[ -n "$BINARY_FILE" ]]; then
    install -m 0755 "$BINARY_FILE" "$destination"
    log "已安装本地二进制"
    return
  fi
  if [[ -n "$BINARY_URL" ]]; then
    archive="$WORK_DIR/custom-download"
    curl --fail --silent --show-error --location "$BINARY_URL" --output "$archive"
    verify_sha256 "$archive" "$BINARY_SHA256"
  else
    arch="$(map_arch)"
    release_json="$WORK_DIR/atlas-release.json"
    curl --fail --silent --show-error --location "https://api.github.com/repos/$REPOSITORY/releases/latest" --output "$release_json"
    asset_url="$(jq -r --arg arch "$arch" '.assets[] | select(.name | test("linux_" + $arch + "\\.tar\\.gz$")) | .browser_download_url' "$release_json" | head -n1)"
    checksum_url="$(jq -r '.assets[] | select(.name | test("checksums\\.txt$")) | .browser_download_url' "$release_json" | head -n1)"
    [[ -n "$asset_url" && "$asset_url" != "null" && -n "$checksum_url" && "$checksum_url" != "null" ]] || die "发布中缺少 Linux $arch 包或 checksums.txt；可改用 --binary-file。"
    archive="$WORK_DIR/$(basename "$asset_url")"
    curl --fail --silent --show-error --location "$asset_url" --output "$archive"
    curl --fail --silent --show-error --location "$checksum_url" --output "$WORK_DIR/checksums.txt"
    expected="$(checksum_from_manifest "$WORK_DIR/checksums.txt" "$(basename "$archive")")"
    [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || die "checksums.txt 中没有找到安装包摘要。"
    verify_sha256 "$archive" "$expected"
  fi
  if tar -tzf "$archive" >/dev/null 2>&1; then
    tar -xzf "$archive" -C "$WORK_DIR"
    local extracted
    extracted="$(find "$WORK_DIR" -type f -name "$PROGRAM" -perm /111 | head -n1)"
    [[ -n "$extracted" ]] || die "安装包中没有可执行的 $PROGRAM。"
    install -m 0755 "$extracted" "$destination"
  else
    install -m 0755 "$archive" "$destination"
  fi
  "$destination" version >/dev/null
  log "Nginx Atlas 二进制安装完成"
}

install_lego() {
  [[ "$SKIP_LEGO" == "false" ]] || { warn "已跳过 lego；DNS-01 自动签发将不可用。"; return; }
  if command -v lego >/dev/null 2>&1; then
    log "已检测到 lego：$(lego --version 2>/dev/null || true)"
    return
  fi
  local arch release_json asset_url checksum_url archive expected
  arch="$(map_arch)"
  release_json="$WORK_DIR/lego-release.json"
  curl --fail --silent --show-error --location "https://api.github.com/repos/go-acme/lego/releases/latest" --output "$release_json"
  asset_url="$(jq -r --arg arch "$arch" '.assets[] | select(.name | test("linux_" + $arch + "\\.tar\\.gz$")) | .browser_download_url' "$release_json" | head -n1)"
  checksum_url="$(jq -r '.assets[] | select(.name | test("checksums\\.txt$")) | .browser_download_url' "$release_json" | head -n1)"
  [[ -n "$asset_url" && "$asset_url" != "null" && -n "$checksum_url" && "$checksum_url" != "null" ]] || die "无法找到 lego Linux 发布包。"
  archive="$WORK_DIR/$(basename "$asset_url")"
  curl --fail --silent --show-error --location "$asset_url" --output "$archive"
  curl --fail --silent --show-error --location "$checksum_url" --output "$WORK_DIR/lego-checksums.txt"
  expected="$(checksum_from_manifest "$WORK_DIR/lego-checksums.txt" "$(basename "$archive")")"
  [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || die "lego checksums.txt 中没有找到安装包摘要。"
  verify_sha256 "$archive" "$expected"
  tar -xzf "$archive" -C "$WORK_DIR"
  [[ -x "$WORK_DIR/lego" ]] || die "lego 安装包中缺少可执行文件。"
  install -m 0755 "$WORK_DIR/lego" "$INSTALL_DIR/lego"
  log "lego DNS-01 客户端安装完成"
}

prepare_directories() {
  install -d -m 0750 "$CONFIG_DIR"
  install -d -m 0700 "$STATE_ROOT" "$STATE_ROOT/agent"
  BACKUP_DIR="/var/backups/nginx-atlas/$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -m 0700 "$BACKUP_DIR"
}

backup_file() {
  local source="$1"
  if [[ -f "$source" ]]; then
    cp -a -- "$source" "$BACKUP_DIR/$(basename "$source")"
  fi
}

write_agent_service() {
  backup_file "$SYSTEMD_DIR/nginx-atlas-agent.service"
  cat >"$SYSTEMD_DIR/nginx-atlas-agent.service" <<'EOF'
[Unit]
Description=Nginx Atlas node agent
After=network-online.target nginx.service
Wants=network-online.target
Requires=nginx.service

[Service]
Type=simple
EnvironmentFile=/etc/nginx-atlas/agent.env
ExecStart=/usr/local/bin/nginx-atlas agent
Restart=always
RestartSec=5s
User=root
Group=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
}

enable_and_restart_service() {
  local unit="$1"
  systemctl enable "$unit"
  systemctl restart "$unit"
}

write_agent_env() {
  local agent_server="$1" token="$2" proxy_header_line=""
  if [[ "$agent_server" == "$CONTROLLER_URL" && -n "$PROXY_TOKEN" ]]; then
    proxy_header_line="ATLAS_PROXY_HEADER_INCLUDE=$PROXY_HEADER_CONFIG"
  fi
  if [[ -n "$token" ]]; then
    rm -f -- "$STATE_ROOT/agent/state.json.revoked"
  fi
  if [[ -s "$STATE_ROOT/agent/state.json" && -f "$CONFIG_DIR/agent.env" ]]; then
    local existing_server
    existing_server="$(read_agent_env_value ATLAS_SERVER_URL)"
    if [[ "$existing_server" == "$agent_server" ]]; then
      if [[ -n "$proxy_header_line" ]] && ! grep -Fxq "$proxy_header_line" "$CONFIG_DIR/agent.env"; then
        printf '%s\n' "$proxy_header_line" >>"$CONFIG_DIR/agent.env"
        chmod 0600 "$CONFIG_DIR/agent.env"
      fi
      log "保留现有节点凭据与 agent.env"
      return
    fi
    if [[ "$existing_server" == "http://127.0.0.1:9090" && "$agent_server" == "$CONTROLLER_URL" ]]; then
      backup_file "$CONFIG_DIR/agent.env"
      sed 's#^ATLAS_SERVER_URL=http://127\.0\.0\.1:9090$#ATLAS_SERVER_URL=http://127.0.0.1:909#' "$CONFIG_DIR/agent.env" >"$WORK_DIR/agent.env"
      install -m 0600 "$WORK_DIR/agent.env" "$CONFIG_DIR/agent.env"
      if [[ -n "$proxy_header_line" ]] && ! grep -Fxq "$proxy_header_line" "$CONFIG_DIR/agent.env"; then
        printf '%s\n' "$proxy_header_line" >>"$CONFIG_DIR/agent.env"
      fi
      log "本机节点已迁移到受保护的主控端口"
      return
    fi
    die "现有节点已绑定 $existing_server；拒绝忽略新的 --server。请先安全卸载旧节点后再迁移。"
  fi
  backup_file "$CONFIG_DIR/agent.env"
  umask 077
  cat >"$CONFIG_DIR/agent.env" <<EOF
ATLAS_SERVER_URL=$agent_server
ATLAS_NODE_NAME=$NODE_NAME
ATLAS_ENROLLMENT_TOKEN=$token
ATLAS_AGENT_STATE_PATH=$STATE_ROOT/agent/state.json
ATLAS_NGINX_CONFIG_DIR=/etc/nginx/conf.d
ATLAS_SSL_ROOT=/etc/ssl
ATLAS_DATA_ROOT=$STATE_ROOT/agent
ATLAS_POLL_INTERVAL=10s
ATLAS_REPOSITORY=$REPOSITORY
$proxy_header_line
EOF
  chmod 0600 "$CONFIG_DIR/agent.env"
}

write_proxy_header_config() {
  [[ -n "$PROXY_TOKEN" ]] || die "反向代理凭据为空。"
  umask 077
  printf 'proxy_set_header X-Atlas-Proxy %s;\n' "$PROXY_TOKEN" >"$WORK_DIR/proxy-token.conf"
  install -m 0600 -o root -g root "$WORK_DIR/proxy-token.conf" "$PROXY_HEADER_CONFIG"
}

install_agent_mode() {
  write_agent_env "$SERVER_URL" "$ENROLLMENT_TOKEN"
  write_agent_service
  systemctl daemon-reload
  enable_and_restart_service nginx-atlas-agent.service
  report_certificate_inventory
  log "节点代理已启动；可用 journalctl -u nginx-atlas-agent -f 查看注册进度。"
}

create_server_user() {
  if ! id nginx-atlas >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE_ROOT/server" --shell /usr/sbin/nologin nginx-atlas
  fi
  prepare_server_state_directory nginx-atlas nginx-atlas
}

prepare_server_state_directory() {
  local owner="$1" group="$2"
  chown root:"$group" "$STATE_ROOT"
  chmod 0710 "$STATE_ROOT"
  install -d -m 0700 -o "$owner" -g "$group" "$STATE_ROOT/server"
}

write_server_env() {
  if [[ -f "$CONFIG_DIR/server.env" ]]; then
    log "保留现有 server.env 与主密钥"
    ADMIN_TOKEN="$(sed -n 's/^ATLAS_ADMIN_TOKEN=//p' "$CONFIG_DIR/server.env" | head -n1)"
    [[ -n "$ADMIN_TOKEN" ]] || die "现有 server.env 缺少 ATLAS_ADMIN_TOKEN。"
    LOCAL_TOKEN="$(sed -n 's/^ATLAS_LOCAL_TOKEN=//p' "$CONFIG_DIR/server.env" | head -n1)"
    PROXY_TOKEN="$(sed -n 's/^ATLAS_PROXY_TOKEN=//p' "$CONFIG_DIR/server.env" | head -n1)"
    if [[ -z "$LOCAL_TOKEN" || -z "$PROXY_TOKEN" ]]; then
      local recovery_secrets
      recovery_secrets="$($INSTALL_DIR/$PROGRAM generate-secrets)"
      if [[ -z "$LOCAL_TOKEN" ]]; then
        LOCAL_TOKEN="$(printf '%s\n' "$recovery_secrets" | sed -n 's/^ATLAS_LOCAL_TOKEN=//p')"
        [[ -n "$LOCAL_TOKEN" ]] || die "无法生成本机恢复凭据。"
        printf 'ATLAS_LOCAL_TOKEN=%s\n' "$LOCAL_TOKEN" >>"$CONFIG_DIR/server.env"
      fi
      if [[ -z "$PROXY_TOKEN" ]]; then
        PROXY_TOKEN="$(printf '%s\n' "$recovery_secrets" | sed -n 's/^ATLAS_PROXY_TOKEN=//p')"
        [[ -n "$PROXY_TOKEN" ]] || die "无法生成反向代理凭据。"
        printf 'ATLAS_PROXY_TOKEN=%s\n' "$PROXY_TOKEN" >>"$CONFIG_DIR/server.env"
      fi
      chown nginx-atlas:nginx-atlas "$CONFIG_DIR/server.env"
      chmod 0600 "$CONFIG_DIR/server.env"
    fi
    if ! grep -q '^ATLAS_REPOSITORY=' "$CONFIG_DIR/server.env"; then
      printf 'ATLAS_REPOSITORY=%s\n' "$REPOSITORY" >>"$CONFIG_DIR/server.env"
      chown nginx-atlas:nginx-atlas "$CONFIG_DIR/server.env"
      chmod 0600 "$CONFIG_DIR/server.env"
    fi
    if grep -Fxq 'ATLAS_ADDR=127.0.0.1:9090' "$CONFIG_DIR/server.env"; then
      backup_file "$CONFIG_DIR/server.env"
      sed 's/^ATLAS_ADDR=127\.0\.0\.1:9090$/ATLAS_ADDR=127.0.0.1:909/' "$CONFIG_DIR/server.env" >"$WORK_DIR/server.env"
      install -m 0600 -o nginx-atlas -g nginx-atlas "$WORK_DIR/server.env" "$CONFIG_DIR/server.env"
      log "主控已迁移到仅特权服务可占用的本机端口"
    fi
    return
  fi
  local secrets master_key
  secrets="$($INSTALL_DIR/$PROGRAM generate-secrets)"
  master_key="$(printf '%s\n' "$secrets" | sed -n 's/^ATLAS_MASTER_KEY=//p')"
  ADMIN_TOKEN="$(printf '%s\n' "$secrets" | sed -n 's/^ATLAS_ADMIN_TOKEN=//p')"
  LOCAL_TOKEN="$(printf '%s\n' "$secrets" | sed -n 's/^ATLAS_LOCAL_TOKEN=//p')"
  PROXY_TOKEN="$(printf '%s\n' "$secrets" | sed -n 's/^ATLAS_PROXY_TOKEN=//p')"
  [[ -n "$master_key" && -n "$ADMIN_TOKEN" && -n "$LOCAL_TOKEN" && -n "$PROXY_TOKEN" ]] || die "无法生成主控密钥。"
  umask 077
  cat >"$CONFIG_DIR/server.env" <<EOF
ATLAS_ADDR=$CONTROLLER_ADDR
ATLAS_PUBLIC_URL=$PUBLIC_URL
ATLAS_STATE_PATH=$STATE_ROOT/server/state.json
ATLAS_MASTER_KEY=$master_key
ATLAS_ADMIN_TOKEN=$ADMIN_TOKEN
ATLAS_LOCAL_TOKEN=$LOCAL_TOKEN
ATLAS_PROXY_TOKEN=$PROXY_TOKEN
ATLAS_REPOSITORY=$REPOSITORY
EOF
  ADMIN_TOKEN_CREATED="true"
  chown nginx-atlas:nginx-atlas "$CONFIG_DIR/server.env"
  chmod 0600 "$CONFIG_DIR/server.env"
}

write_server_service() {
  backup_file "$SYSTEMD_DIR/nginx-atlas-server.service"
  cat >"$SYSTEMD_DIR/nginx-atlas-server.service" <<'EOF'
[Unit]
Description=Nginx Atlas controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/nginx-atlas/server.env
ExecStart=/usr/local/bin/nginx-atlas server
Restart=always
RestartSec=4s
User=nginx-atlas
Group=nginx-atlas
UMask=0077
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/nginx-atlas/server
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
}

configure_panel_nginx() {
  local cert_dir="/etc/ssl/$PANEL_DOMAIN"
  if panel_is_agent_managed; then
    secure_agent_managed_panel_proxy
    log "$PANEL_DOMAIN 已由本机节点代理管理，已同步受保护的主控代理配置。"
    return
  fi
  if [[ ! -r "$cert_dir/fullchain.pem" || ! -r "$cert_dir/privkey.pem" ]]; then
    warn "未发现 $cert_dir/fullchain.pem 与 privkey.pem，未创建公网面板站点。"
    warn "请先由外部反向代理将 $PUBLIC_URL 转发到 $CONTROLLER_ADDR，或放入证书后重新运行安装器。"
    warn "代理必须携带 server.env 中的 ATLAS_PROXY_TOKEN；同机 Nginx 可 include $PROXY_HEADER_CONFIG，并覆盖 X-Real-IP。"
    return
  fi
  backup_file "$NGINX_PANEL_CONFIG"
  cat >"$NGINX_PANEL_CONFIG" <<EOF
# Managed by the Nginx Atlas installer.
server {
    listen 80;
    listen [::]:80;
    server_name $PANEL_DOMAIN;
    return 308 https://$PANEL_DOMAIN\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $PANEL_DOMAIN;

    ssl_certificate $cert_dir/fullchain.pem;
    ssl_certificate_key $cert_dir/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=15552000" always;
    client_max_body_size 8m;

    location = /api/v1/events {
        proxy_pass $CONTROLLER_URL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        include $PROXY_HEADER_CONFIG;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        proxy_pass $CONTROLLER_URL;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        include $PROXY_HEADER_CONFIG;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
  chown root:root "$NGINX_PANEL_CONFIG"
  chmod 0600 "$NGINX_PANEL_CONFIG"
  if ! nginx -t; then
    if [[ -f "$BACKUP_DIR/$(basename "$NGINX_PANEL_CONFIG")" ]]; then
      cp -a -- "$BACKUP_DIR/$(basename "$NGINX_PANEL_CONFIG")" "$NGINX_PANEL_CONFIG"
    else
      rm -f -- "$NGINX_PANEL_CONFIG"
    fi
    nginx -t || true
    die "面板 Nginx 配置验证失败，已恢复旧文件。"
  fi
  systemctl reload nginx
  log "已为 $PANEL_DOMAIN 配置 HTTPS 反向代理"
}

secure_agent_managed_panel_proxy() {
  local managed_config="$NGINX_CONFIG_DIR/atlas-$PANEL_DOMAIN.conf"
  local staged_config="$WORK_DIR/$(basename "$managed_config")"
  backup_file "$managed_config"
  sed 's#proxy_pass http://127\.0\.0\.1:9090;#proxy_pass http://127.0.0.1:909;#' "$managed_config" >"$staged_config"
  if ! grep -Fq "include $PROXY_HEADER_CONFIG;" "$staged_config"; then
    sed "/proxy_set_header X-Real-IP/a\\        include $PROXY_HEADER_CONFIG;" "$staged_config" >"$WORK_DIR/managed-panel.conf"
    mv -- "$WORK_DIR/managed-panel.conf" "$staged_config"
  fi
  install -m 0600 -o root -g root "$staged_config" "$managed_config"
  if ! nginx -t; then
    cp -a -- "$BACKUP_DIR/$(basename "$managed_config")" "$managed_config"
    nginx -t || true
    die "节点托管的面板配置验证失败，已恢复旧文件。"
  fi
  systemctl reload nginx
}

panel_is_agent_managed() {
  local managed_config="$NGINX_CONFIG_DIR/atlas-$PANEL_DOMAIN.conf"
  if [[ -f "$managed_config" ]] &&
    grep -Fqx '# Managed by Nginx Atlas. Manual changes will be replaced.' "$managed_config" &&
    grep -Fq "server_name $PANEL_DOMAIN;" "$managed_config"; then
    if grep -Eq 'proxy_pass http://127\.0\.0\.1:(909|9090);' "$managed_config"; then
      return 0
    fi
    die "$PANEL_DOMAIN 已由节点代理管理，但上游不是本机主控；拒绝注入主控代理凭据。"
  fi
  return 1
}

wait_for_controller() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl --fail --silent "$CONTROLLER_URL/healthz" >/dev/null; then
      return
    fi
    sleep 1
  done
  journalctl -u nginx-atlas-server --no-pager -n 30 >&2 || true
  die "主控服务未在 30 秒内就绪。"
}

create_local_enrollment() {
  if [[ -s "$STATE_ROOT/agent/state.json" && -f "$CONFIG_DIR/agent.env" ]]; then
    write_agent_env "$CONTROLLER_URL" ""
    log "本机节点已经注册，跳过重新添加。"
    return
  fi
  local payload response token curl_config
  payload="$(jq -cn --arg name "$NODE_NAME" '{name:$name, ttl_minutes:30}')"
  curl_config="$WORK_DIR/controller-curl.conf"
  umask 077
  printf 'header = "Authorization: AtlasLocal %s"\nheader = "Content-Type: application/json"\n' "$LOCAL_TOKEN" >"$curl_config"
  chmod 0600 "$curl_config"
  response="$(curl --fail --silent --show-error --config "$curl_config" -d "$payload" "$CONTROLLER_URL/api/v1/local/enrollments")"
  rm -f -- "$curl_config"
  token="$(printf '%s' "$response" | jq -r '.token')"
  [[ -n "$token" && "$token" != "null" ]] || die "无法生成本机节点添加令牌。"
  write_agent_env "$CONTROLLER_URL" "$token"
}

install_server_mode() {
  create_server_user
  write_server_env
  write_proxy_header_config
  write_server_service
  systemctl daemon-reload
  enable_and_restart_service nginx-atlas-server.service
  wait_for_controller
  configure_panel_nginx
  create_local_enrollment
  write_agent_service
  systemctl daemon-reload
  enable_and_restart_service nginx-atlas-agent.service
  report_certificate_inventory
  printf '\n'
  log "主控安装完成：$PUBLIC_URL"
  if [[ "$ADMIN_TOKEN_CREATED" == "true" ]]; then
    printf '\033[1;33m管理员令牌（请立即保存）：\033[0m %s\n' "$ADMIN_TOKEN"
  else
    log "已保留现有管理员凭据；安装器不会再次输出令牌。"
  fi
  printf '服务状态：systemctl status nginx-atlas-server nginx-atlas-agent\n'
}

report_certificate_inventory() {
  local count
  count="$(find /etc/ssl -mindepth 2 -maxdepth 2 -type f -name fullchain.pem -printf '%h\n' 2>/dev/null | while IFS= read -r directory; do [[ -r "$directory/privkey.pem" ]] && printf '%s\n' "$directory"; done | sort -u | wc -l | tr -d ' ')"
  log "已发现 $count 个符合 /etc/ssl/<域名>/{fullchain.pem,privkey.pem} 的证书目录"
}

main() {
  parse_args "$@"
  require_root
  read_enrollment_token
  validate_args
  if [[ "$MODE" == "uninstall-agent" ]]; then
    uninstall_agent_mode
    return
  fi
  if [[ "$MODE" == "uninstall-server" ]]; then
    uninstall_server_mode
    return
  fi
  detect_package_manager
  WORK_DIR="$(mktemp -d /tmp/nginx-atlas.XXXXXX)"
  install_packages
  prepare_directories
  install_binary
  install_lego
  if [[ "$MODE" == "server" ]]; then
    install_server_mode
  else
    install_agent_mode
  fi
}

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
  main "$@"
fi
