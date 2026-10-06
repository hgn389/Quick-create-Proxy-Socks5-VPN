#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly APP_NAME="Quick Create Proxy SOCKS5 VPN"
readonly APP_VERSION="1.0.0-beta.5"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR

usage() {
  cat <<'EOF'
Usage: ./install.sh --check
       ./install.sh --install [--yes]
       ./install.sh --uninstall [--yes]

  --check       Read-only host and platform preflight.
  --install     Install or upgrade QCP from local verified binaries.
  --uninstall   Remove QCP services and binaries; preserve configuration/data.
  --yes         Accept the displayed change plan without an interactive prompt.
  --help        Show this message.

The panel binds to HTTPS on TCP 22689. Installation opens that port in the
detected host firewall but does not change the existing webserver. WireGuard tools may be installed
from the OS package repository when missing.
EOF
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

info() { printf 'INFO: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
ok() { printf 'PASS: %s\n' "$*"; }

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command is missing: $1"
}

read_os_release() {
  [[ -r /etc/os-release ]] || fail "Cannot read /etc/os-release; unsupported Linux image."
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID,,}"
  OS_VERSION="${VERSION_ID:-unknown}"
}

check_platform() {
  local machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv*|armhf) fail "32-bit ARM ($machine) is not in the v1 beta target matrix." ;;
    *) fail "Unsupported CPU architecture: $machine" ;;
  esac

  [[ "$(uname -s)" == "Linux" ]] || fail "Only Linux is supported."
  [[ -d /run/systemd/system ]] || fail "systemd is not running; this host is unsupported."
  read_os_release

  case "$OS_ID:$OS_VERSION" in
    ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) OS_FAMILY="debian" ;;
    debian:12|debian:13) OS_FAMILY="debian" ;;
    almalinux:8*|almalinux:9*|almalinux:10*) OS_FAMILY="rpm" ;;
    centos:9*|centos:10*)
      [[ "${PRETTY_NAME:-}" == *"Stream"* ]] || fail "CentOS Linux is not supported; use CentOS Stream 9 or 10."
      OS_FAMILY="rpm"
      ;;
    *) fail "Unsupported OS release: ${PRETTY_NAME:-$OS_ID $OS_VERSION}" ;;
  esac

  if [[ "$OS_ID" == "ubuntu" && "$OS_VERSION" == "20.04" ]]; then
    warn "Ubuntu 20.04 is legacy; confirm security updates (Ubuntu Pro/ESM where required)."
  fi

  ok "Linux distribution: ${PRETTY_NAME:-$OS_ID $OS_VERSION} ($OS_FAMILY packages)"
  ok "Architecture: $ARCH"
  ok "systemd is available"
}

check_wireguard() {
  local kernel module_present=false tools_present=false
  kernel="$(uname -r)"

  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
    tools_present=true
  fi

  if [[ -d "/sys/module/wireguard" ]]; then
    module_present=true
  elif command -v modprobe >/dev/null 2>&1 && modprobe -n wireguard >/dev/null 2>&1; then
    module_present=true
  fi

  if [[ "$tools_present" == true ]]; then
    ok "WireGuard tools are already installed"
  else
    info "WireGuard tools are not installed; the installer will need the OS package manager."
  fi

  if [[ "$module_present" == true ]]; then
    ok "WireGuard kernel module is available for kernel $kernel"
  else
    warn "WireGuard kernel support is not currently detectable for kernel $kernel. VPN setup must stop until this kernel provides WireGuard. No kernel will be compiled or replaced automatically."
  fi
}

check_resources() {
  local mem_kib avail_kib root_avail_kib
  mem_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || true)"
  avail_kib="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || true)"
  root_avail_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
  [[ "$mem_kib" =~ ^[0-9]+$ ]] || mem_kib=0
  [[ "$avail_kib" =~ ^[0-9]+$ ]] || avail_kib=0
  [[ "$root_avail_kib" =~ ^[0-9]+$ ]] || root_avail_kib=0

  printf 'INFO: RAM total: %s MiB; currently available: %s MiB\n' \
    "$((mem_kib / 1024))" "$((avail_kib / 1024))"
  printf 'INFO: Free space on /: %s MiB\n' "$((root_avail_kib / 1024))"
  (( root_avail_kib >= 256 * 1024 )) || warn "Less than 256 MiB is free on /; installation should stop unless space is freed."
}

check_network_helpers() {
  for cmd in ip ss awk df curl sha256sum getent systemctl; do require_command "$cmd"; done
  ok "Basic network and resource inspection commands are available"
}

select_payload() {
  local major
  major="$(printf '%s' "$OS_VERSION" | cut -d. -f1)"
  case "$OS_ID:$OS_VERSION" in
    ubuntu:20.04) ENGINE_VARIANT="ubuntu20" ;;
    ubuntu:*|debian:*) ENGINE_VARIANT="deb" ;;
    almalinux:*|centos:*) ENGINE_VARIANT="el$major" ;;
  esac
  QCP_PAYLOAD="$SCRIPT_DIR/dist/go/qcp-linux-$ARCH"
  ENGINE_PAYLOAD="$SCRIPT_DIR/dist/vendor/3proxy/$ENGINE_VARIANT/$ARCH/3proxy"
}

verify_one_checksum() {
  local manifest="$1" relative_name="$2" actual_file="$3" expected
  [[ -r "$manifest" && -f "$actual_file" ]] || fail "Missing release payload or checksum: $actual_file"
  expected="$(awk -v name="$relative_name" '$2==name {print $1; exit}' "$manifest")"
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || fail "Missing checksum entry for $relative_name"
  printf '%s  %s\n' "$expected" "$actual_file" | sha256sum -c - >/dev/null ||
    fail "Checksum failed for $actual_file"
}

check_payload() {
  select_payload
  if [[ ! -f "$QCP_PAYLOAD" || ! -f "$ENGINE_PAYLOAD" ]]; then
    warn "Local payload is incomplete for $OS_ID $OS_VERSION / $ARCH ($ENGINE_VARIANT)."
    return 1
  fi
  verify_one_checksum "$SCRIPT_DIR/dist/go/SHA256SUMS" "qcp-linux-$ARCH" "$QCP_PAYLOAD"
  verify_one_checksum "$SCRIPT_DIR/dist/vendor/3proxy/SHA256SUMS" "./$ENGINE_VARIANT/$ARCH/3proxy" "$ENGINE_PAYLOAD"
  ok "Local binaries match build-time checksums"
  if command -v ldd >/dev/null 2>&1; then
    local dependencies
    dependencies="$(ldd "$ENGINE_PAYLOAD" 2>&1)" || {
      if [[ "$ENGINE_VARIANT" != ubuntu20 || ( "$dependencies" != *"not a dynamic executable"* && "$dependencies" != *"statically linked"* ) ]]; then
        warn "The selected 3proxy binary cannot be inspected by ldd."
        return 1
      fi
    }
    if printf '%s\n' "$dependencies" | grep -q 'not found'; then
      warn "The selected 3proxy binary has missing shared libraries on this host."
      return 1
    fi
  fi
  ok "Selected proxy engine: 3proxy LTS ($ENGINE_VARIANT / $ARCH)"
}

install_wireguard_dependencies() {
  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1 && command -v nft >/dev/null 2>&1; then
    return 0
  fi
  info "Installing WireGuard tools and nftables from configured OS repositories."
  if [[ "$OS_FAMILY" == debian ]]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wireguard-tools nftables
  else
    dnf install -y wireguard-tools nftables
  fi
}

check_panel_port() {
  if ss -H -ltn "( sport = :22689 )" 2>/dev/null | grep -q .; then
    local panel_pid
    panel_pid="$(systemctl show --property=MainPID --value qcp-panel.service 2>/dev/null || true)"
    if [[ "$EUID" -eq 0 && "$panel_pid" =~ ^[1-9][0-9]*$ ]] &&
       ss -H -ltnp "( sport = :22689 )" 2>/dev/null | grep -q "pid=$panel_pid,"; then
      info "Panel port 22689 is in use by an existing QCP installation."
    else
      warn "TCP port 22689 is in use by another service."
      return 1
    fi
  fi
  ok "Panel TCP port 22689 is available"
}

wait_for_panel() {
  local attempt
  for ((attempt = 1; attempt <= 25; attempt++)); do
    if curl --fail --silent --max-time 1 \
      --cacert /etc/qcp/panel.crt https://127.0.0.1:22689/login >/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  warn "Panel did not become ready on HTTPS port 22689. Recent service diagnostics follow."
  systemctl status qcp-agent.service qcp-panel.service --no-pager -l >&2 || true
  journalctl -u qcp-agent.service -u qcp-panel.service -n 40 --no-pager >&2 || true
  return 1
}

valid_ipv4() {
  local address="$1" part
  local -a parts
  [[ "$address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a parts <<<"$address"
  [[ "${#parts[@]}" -eq 4 ]] || return 1
  for part in "${parts[@]}"; do
    [[ "$part" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    (( 10#$part <= 255 )) || return 1
  done
}

detect_panel_ip() {
  PANEL_IP="${QCP_PANEL_IP:-}"
  if [[ -z "$PANEL_IP" ]]; then
    PANEL_IP="$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
  fi
  if [[ -z "$PANEL_IP" ]]; then
    PANEL_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
    warn "Public IPv4 discovery failed; using the default-interface IPv4 address. Set QCP_PANEL_IP if this is not reachable externally."
  fi
  [[ -n "$PANEL_IP" ]] || fail "Cannot determine a panel IPv4 address; set QCP_PANEL_IP."
  valid_ipv4 "$PANEL_IP" || fail "Panel address is not a valid IPv4 address: $PANEL_IP"
  info "Panel address candidate: $PANEL_IP"
}

print_provider_firewall_hint() {
  local product=""
  if [[ -r /sys/class/dmi/id/product_name ]]; then
    product="$(tr '[:upper:]' '[:lower:]' </sys/class/dmi/id/product_name)"
  fi
  case "$product" in
    *google*) warn "Google Cloud VPC firewall must also allow ingress TCP 22689; opening SSH port 22 does not open the panel port." ;;
    *vultr*) warn "Vultr Firewall must also allow inbound TCP 22689 when a Vultr Firewall Group is attached." ;;
    *) info "If the page does not open externally, allow inbound TCP 22689 in the VPS provider firewall/security group." ;;
  esac
}

confirm_action() {
  local answer
  [[ "$AUTO_YES" == true ]] && return 0
  [[ -t 0 ]] || fail "Interactive confirmation is required; use --yes only after reviewing the plan."
  read -r -p "Continue? [y/N] " answer
  [[ "$answer" == y || "$answer" == Y ]] || fail "Cancelled."
}

ensure_system_users() {
  if ! getent group qcp >/dev/null; then groupadd --system qcp; fi
  if ! getent passwd qcp >/dev/null; then
    useradd --system --gid qcp --home-dir /var/lib/qcp --shell /usr/sbin/nologin \
      --comment 'QCP web panel' qcp
  fi
  if ! getent group qcp-proxy >/dev/null; then groupadd --system qcp-proxy; fi
  if ! getent passwd qcp-proxy >/dev/null; then
    useradd --system --gid qcp-proxy --home-dir /var/lib/qcp \
      --shell /usr/sbin/nologin --comment 'QCP proxy engine' qcp-proxy
  fi
}

print_install_plan() {
  cat <<EOF
Change plan:
  OS/architecture: $OS_ID $OS_VERSION / $ARCH
  Application:      /usr/local/bin/qcp
  Proxy engine:     /usr/local/libexec/qcp/3proxy
  Configuration:    /etc/qcp
  State/backup:     /var/lib/qcp
  Services:         qcp-agent.service, qcp-panel.service, qcp-firewall.service, qcp-proxy@.service
  Panel listener:   HTTPS on 0.0.0.0:22689
  Login URL:        https://$PANEL_IP:22689
  New install login: admin / 12345687; password change required at first login
  TLS:              self-signed certificate; fingerprint printed during install
  Firewall:         add a QCP-owned allow rule for TCP 22689
  Existing QCP proxy connections may briefly stop during an upgrade.
  Dependencies:     wireguard-tools and nftables from OS repositories if missing
  Webserver:        no changes
  Proxy listeners:  none until an admin creates one
EOF
}

backup_existing() {
  BACKUP_DIR="/var/lib/qcp/backups/install-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  install -d -m 0700 "$BACKUP_DIR"
  local item label
  for item in \
    /usr/local/bin/qcp \
    /usr/local/libexec/qcp/3proxy \
    /etc/systemd/system/qcp-agent.service \
    /etc/systemd/system/qcp-panel.service \
    /etc/systemd/system/qcp-firewall.service \
    /etc/systemd/system/qcp-proxy@.service \
    /etc/qcp/admin.hash \
    /etc/qcp/panel.crt \
    /etc/qcp/panel.key \
    /etc/qcp/panel.host \
    /etc/qcp/admin.must-change \
    /var/lib/qcp/panel-firewall.json; do
    label="$(printf '%s' "$item" | tr / _)"
    if [[ -e "$item" ]]; then cp -a -- "$item" "$BACKUP_DIR/$label"; fi
  done
}

restore_one() {
  local target="$1" label
  label="$(printf '%s' "$target" | tr / _)"
  if [[ -e "$BACKUP_DIR/$label" ]]; then
    cp -a -- "$BACKUP_DIR/$label" "$target"
  else
    rm -f -- "$target"
  fi
}

rollback_install() {
  trap - ERR
  set +e
  warn "Installation failed. Restoring previous QCP binaries and units."
  if [[ -x /usr/local/bin/qcp ]]; then
    /usr/local/bin/qcp proxy-firewalls down >/dev/null 2>&1 || true
    /usr/local/bin/qcp firewall down >/dev/null 2>&1 || true
  fi
  systemctl stop qcp-panel.service qcp-firewall.service qcp-agent.service >/dev/null 2>&1
  local item
  for item in \
    /usr/local/bin/qcp \
    /usr/local/libexec/qcp/3proxy \
    /etc/systemd/system/qcp-agent.service \
    /etc/systemd/system/qcp-panel.service \
    /etc/systemd/system/qcp-firewall.service \
    /etc/systemd/system/qcp-proxy@.service \
    /etc/qcp/admin.hash \
    /etc/qcp/panel.crt \
    /etc/qcp/panel.key \
    /etc/qcp/panel.host \
    /etc/qcp/admin.must-change \
    /var/lib/qcp/panel-firewall.json; do
    restore_one "$item"
  done
  systemctl daemon-reload >/dev/null 2>&1
  if [[ "$HAD_AGENT" == true ]]; then systemctl start qcp-agent.service; else systemctl disable qcp-agent.service >/dev/null 2>&1; fi
  if [[ "$HAD_FIREWALL" == true ]]; then systemctl start qcp-firewall.service; else systemctl disable qcp-firewall.service >/dev/null 2>&1; fi
  if [[ "$HAD_PANEL" == true ]]; then systemctl start qcp-panel.service; else systemctl disable qcp-panel.service >/dev/null 2>&1; fi
  for item in "${ACTIVE_PROXIES[@]}"; do systemctl start "$item"; done
}

install_qcp() {
  [[ "$EUID" -eq 0 ]] || fail "Installation requires root."
  (( $(df -Pk / | awk 'NR==2 {print $4}') >= 256 * 1024 )) || fail "At least 256 MiB of free root disk space is required."
  check_payload || fail "A compatible release payload is required."
  check_panel_port || fail "Panel port conflict."
  detect_panel_ip
  print_install_plan
  confirm_action
  if ! install_wireguard_dependencies; then
    warn "WireGuard tools could not be installed; proxy and panel installation will continue. VPN activation requires wireguard-tools and nftables."
  fi
  HAD_AGENT=false
  HAD_PANEL=false
  HAD_FIREWALL=false
  CREATED_ADMIN=false
  ACTIVE_PROXIES=()
  systemctl is-active --quiet qcp-agent.service 2>/dev/null && HAD_AGENT=true
  systemctl is-active --quiet qcp-panel.service 2>/dev/null && HAD_PANEL=true
  systemctl is-active --quiet qcp-firewall.service 2>/dev/null && HAD_FIREWALL=true
  ensure_system_users
  install -d -m 0711 -o root -g root /etc/qcp
  install -d -m 0750 -o root -g qcp-proxy /etc/qcp/proxies
  install -d -m 0700 -o root -g root /var/lib/qcp
  install -d -m 0755 -o root -g root /usr/local/libexec/qcp
  backup_existing
  trap 'rollback_install; exit 1' ERR
  local config id unit
  for config in /etc/qcp/proxies/*.cfg; do
    [[ -e "$config" ]] || continue
    id="$(basename "$config" .cfg)"
    [[ "$id" =~ ^[a-f0-9]{16}$ ]] || continue
    unit="qcp-proxy@$id.service"
    if systemctl is-active --quiet "$unit"; then
      ACTIVE_PROXIES+=("$unit")
      systemctl stop "$unit"
    fi
  done
  systemctl stop qcp-panel.service qcp-firewall.service qcp-agent.service >/dev/null 2>&1 || true
  install -m 0755 -o root -g root "$QCP_PAYLOAD" /usr/local/bin/qcp
  install -m 0755 -o root -g root "$ENGINE_PAYLOAD" /usr/local/libexec/qcp/3proxy
  install -m 0644 -o root -g root "$SCRIPT_DIR/systemd/qcp-agent.service" /etc/systemd/system/qcp-agent.service
  install -m 0644 -o root -g root "$SCRIPT_DIR/systemd/qcp-panel.service" /etc/systemd/system/qcp-panel.service
  install -m 0644 -o root -g root "$SCRIPT_DIR/systemd/qcp-firewall.service" /etc/systemd/system/qcp-firewall.service
  install -m 0644 -o root -g root "$SCRIPT_DIR/systemd/qcp-proxy@.service" /etc/systemd/system/qcp-proxy@.service
  systemctl daemon-reload
  if [[ ! -f /etc/qcp/admin.hash ]]; then
    /usr/local/bin/qcp admin bootstrap
    CREATED_ADMIN=true
  fi
  /usr/local/bin/qcp panel-cert "$PANEL_IP"
  systemctl enable --now qcp-agent.service qcp-firewall.service qcp-panel.service
  for unit in "${ACTIVE_PROXIES[@]}"; do systemctl start "$unit"; done
  systemctl is-active --quiet qcp-agent.service
  systemctl is-active --quiet qcp-panel.service
  systemctl is-active --quiet qcp-firewall.service
  wait_for_panel
  trap - ERR
  ok "QCP installed. Login: https://$PANEL_IP:22689"
  if [[ "$CREATED_ADMIN" == true ]]; then
    info "Web panel username: admin"
    info "Web panel password: 12345687"
    warn "The panel requires this default password to be changed immediately after first login."
  fi
  info "The host firewall was configured for TCP 22689."
  print_provider_firewall_hint
  info "Backup of replaced QCP files: $BACKUP_DIR"
}

uninstall_qcp() {
  [[ "$EUID" -eq 0 ]] || fail "Uninstallation requires root."
  cat <<EOF
Removal plan:
  Stop and disable QCP WireGuard, panel, agent and proxy services.
  Remove QCP-owned service units and binaries.
  Preserve /etc/qcp and /var/lib/qcp, including credentials and backups.
  Remove QCP-owned panel/proxy port rules and the WireGuard NAT table. Leave other firewall rules untouched.
EOF
  confirm_action
  local config id
  systemctl disable --now qcp-firewall.service >/dev/null 2>&1 || true
  if [[ -x /usr/local/bin/qcp ]]; then /usr/local/bin/qcp firewall down >/dev/null 2>&1 || true; fi
  systemctl disable --now wg-quick@qcp-wg0.service >/dev/null 2>&1 || true
  if [[ -x /usr/local/bin/qcp ]]; then /usr/local/bin/qcp wg-route down >/dev/null 2>&1 || true; fi
  if command -v nft >/dev/null 2>&1; then nft delete table ip qcp_wg_nat >/dev/null 2>&1 || true; fi
  if [[ -d /etc/qcp/proxies ]]; then
    for config in /etc/qcp/proxies/*.cfg; do
      [[ -e "$config" ]] || continue
      id="$(basename "$config" .cfg)"
      [[ "$id" =~ ^[a-f0-9]{16}$ ]] || continue
      systemctl disable --now "qcp-proxy@$id.service" >/dev/null 2>&1 || true
    done
  fi
  if [[ -x /usr/local/bin/qcp ]]; then /usr/local/bin/qcp proxy-firewalls down >/dev/null 2>&1 || true; fi
  systemctl disable --now qcp-panel.service qcp-agent.service >/dev/null 2>&1 || true
  rm -f -- \
    /etc/systemd/system/qcp-agent.service \
    /etc/systemd/system/qcp-panel.service \
    /etc/systemd/system/qcp-firewall.service \
    /etc/systemd/system/qcp-proxy@.service \
    /usr/local/bin/qcp \
    /usr/local/libexec/qcp/3proxy
  systemctl daemon-reload
  ok "QCP application services removed. Configuration and data were preserved."
}

main() {
  local mode="${1:---help}"
  AUTO_YES=false
  if [[ "${2:-}" == --yes ]]; then AUTO_YES=true; fi
  if [[ $# -gt 2 || ( $# -eq 2 && "${2:-}" != --yes ) ]]; then
    usage >&2
    fail "Unknown arguments."
  fi
  case "$mode" in
    --help|-h) usage; exit 0 ;;
    --check|--install|--uninstall) ;;
    *) usage >&2; fail "Unknown mode: $mode" ;;
  esac
  if [[ "$mode" == --uninstall ]]; then
    uninstall_qcp
    return
  fi

  info "$APP_NAME $APP_VERSION — $mode"
  check_platform
  check_network_helpers
  check_resources
  check_wireguard
  case "$mode" in
    --check)
      check_payload || true
      check_panel_port || true
      detect_panel_ip
      info "Preflight finished. No packages, users, services, firewall rules, or files were changed."
      ;;
    --install) install_qcp ;;
    --uninstall) uninstall_qcp ;;
  esac
}

main "$@"
