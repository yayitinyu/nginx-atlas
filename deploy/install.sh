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
BACKUP_DIR=""
WORK_DIR=""

log() { printf '\033[1;32m[atlas]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[atlas]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[atlas]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  install.sh server --public-url https://atlas.example.com [--panel-domain atlas.example.com]
  install.sh agent --server https://atlas.example.com --token TOKEN [--name Tokyo-02]
  install.sh uninstall-agent

Options:
  --binary-file PATH       Install a locally built nginx-atlas binary.
  --binary-url URL         Download a binary or tar.gz from a custom URL.
  --binary-sha256 SHA256   Required with --binary-url.
  --repo OWNER/REPO        GitHub repository used for the latest release.
  --skip-lego              Do not install the lego DNS-01 client.

The server mode also installs a local node agent. Existing state, secrets, and
service configuration are preserved on reruns.
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
    server|agent|uninstall-agent) ;;
    -h|--help|help) usage; exit 0 ;;
    *) die "未知安装模式：$MODE" ;;
  esac
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server) [[ $# -ge 2 ]] || die "--server 缺少参数"; SERVER_URL="$2"; shift 2 ;;
      --public-url) [[ $# -ge 2 ]] || die "--public-url 缺少参数"; PUBLIC_URL="$2"; shift 2 ;;
      --panel-domain) [[ $# -ge 2 ]] || die "--panel-domain 缺少参数"; PANEL_DOMAIN="$2"; shift 2 ;;
      --token) [[ $# -ge 2 ]] || die "--token 缺少参数"; ENROLLMENT_TOKEN="$2"; shift 2 ;;
      --name) [[ $# -ge 2 ]] || die "--name 缺少参数"; NODE_NAME="$2"; shift 2 ;;
      --binary-file) [[ $# -ge 2 ]] || die "--binary-file 缺少参数"; BINARY_FILE="$2"; shift 2 ;;
      --binary-url) [[ $# -ge 2 ]] || die "--binary-url 缺少参数"; BINARY_URL="$2"; shift 2 ;;
      --binary-sha256) [[ $# -ge 2 ]] || die "--binary-sha256 缺少参数"; BINARY_SHA256="$2"; shift 2 ;;
      --repo) [[ $# -ge 2 ]] || die "--repo 缺少参数"; REPOSITORY="$2"; shift 2 ;;
      --skip-lego) SKIP_LEGO="true"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "未知参数：$1" ;;
    esac
  done
}

validate_args() {
  if [[ "$MODE" == "uninstall-agent" ]]; then
    return
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

uninstall_agent_mode() {
  log "停止并移除 Nginx Atlas 节点代理"
  systemctl disable --now nginx-atlas-agent.service >/dev/null 2>&1 || true
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
  local agent_server="$1" token="$2"
  if [[ -s "$STATE_ROOT/agent/state.json" && -f "$CONFIG_DIR/agent.env" ]]; then
    log "保留现有节点凭据与 agent.env"
    return
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
EOF
  chmod 0600 "$CONFIG_DIR/agent.env"
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
    if ! grep -q '^ATLAS_REPOSITORY=' "$CONFIG_DIR/server.env"; then
      printf 'ATLAS_REPOSITORY=%s\n' "$REPOSITORY" >>"$CONFIG_DIR/server.env"
      chown nginx-atlas:nginx-atlas "$CONFIG_DIR/server.env"
      chmod 0600 "$CONFIG_DIR/server.env"
    fi
    return
  fi
  local secrets master_key
  secrets="$($INSTALL_DIR/$PROGRAM generate-secrets)"
  master_key="$(printf '%s\n' "$secrets" | sed -n 's/^ATLAS_MASTER_KEY=//p')"
  ADMIN_TOKEN="$(printf '%s\n' "$secrets" | sed -n 's/^ATLAS_ADMIN_TOKEN=//p')"
  [[ -n "$master_key" && -n "$ADMIN_TOKEN" ]] || die "无法生成主控密钥。"
  umask 077
  cat >"$CONFIG_DIR/server.env" <<EOF
ATLAS_ADDR=127.0.0.1:9090
ATLAS_PUBLIC_URL=$PUBLIC_URL
ATLAS_STATE_PATH=$STATE_ROOT/server/state.json
ATLAS_MASTER_KEY=$master_key
ATLAS_ADMIN_TOKEN=$ADMIN_TOKEN
ATLAS_REPOSITORY=$REPOSITORY
EOF
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
    log "$PANEL_DOMAIN 已由本机节点代理管理，跳过重复的静态面板配置。"
    return
  fi
  if [[ ! -r "$cert_dir/fullchain.pem" || ! -r "$cert_dir/privkey.pem" ]]; then
    warn "未发现 $cert_dir/fullchain.pem 与 privkey.pem，未创建公网面板站点。"
    warn "请先由外部反向代理将 $PUBLIC_URL 转发到 127.0.0.1:9090，或放入证书后重新运行安装器。"
    return
  fi
  backup_file "$NGINX_PANEL_CONFIG"
  cat >"$NGINX_PANEL_CONFIG" <<EOF
# Managed by the Nginx Atlas installer.
server {
    listen 80;
    listen [::]:80;
    server_name $PANEL_DOMAIN;
    return 308 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $PANEL_DOMAIN;

    ssl_certificate $cert_dir/fullchain.pem;
    ssl_certificate_key $cert_dir/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 8m;

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
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

panel_is_agent_managed() {
  local managed_config="$NGINX_CONFIG_DIR/atlas-$PANEL_DOMAIN.conf"
  [[ -f "$managed_config" ]] &&
    grep -Fqx '# Managed by Nginx Atlas. Manual changes will be replaced.' "$managed_config" &&
    grep -Fq "server_name $PANEL_DOMAIN;" "$managed_config"
}

wait_for_controller() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl --fail --silent http://127.0.0.1:9090/healthz >/dev/null; then
      return
    fi
    sleep 1
  done
  journalctl -u nginx-atlas-server --no-pager -n 30 >&2 || true
  die "主控服务未在 30 秒内就绪。"
}

create_local_enrollment() {
  if [[ -s "$STATE_ROOT/agent/state.json" && -f "$CONFIG_DIR/agent.env" ]]; then
    log "本机节点已经注册，跳过重新添加。"
    return
  fi
  local payload response token
  payload="$(jq -cn --arg name "$NODE_NAME" '{name:$name, ttl_minutes:30}')"
  response="$(curl --fail --silent --show-error -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d "$payload" http://127.0.0.1:9090/api/v1/enrollments)"
  token="$(printf '%s' "$response" | jq -r '.token')"
  [[ -n "$token" && "$token" != "null" ]] || die "无法生成本机节点添加令牌。"
  write_agent_env "http://127.0.0.1:9090" "$token"
}

install_server_mode() {
  create_server_user
  write_server_env
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
  printf '\033[1;33m管理员令牌（请立即保存）：\033[0m %s\n' "$ADMIN_TOKEN"
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
  validate_args
  if [[ "$MODE" == "uninstall-agent" ]]; then
    uninstall_agent_mode
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
