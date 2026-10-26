#!/usr/bin/env bash
# vps-relay 一键安装：sing-box（三个节点）+ 网页管理面板
#   安装/升级: bash install.sh
#   卸载:      bash install.sh uninstall
# 可选环境变量: SB_VERSION REPO BRANCH SERVER_IP NODE_NAME REALITY_SNI
#              VLESS_PORT HY2_PORT SMART_PORT PANEL_PORT B_LINK DOMAIN ENABLE_BBR=0
set -euo pipefail

SB_VERSION="${SB_VERSION:-1.14.4}"
REPO="${REPO:-ryanlikaige/vps-relay}"
BRANCH="${BRANCH:-main}"
OPT=/opt/vps-relay
ETC=/etc/vps-relay

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
die() { red "错误: $*"; exit 1; }

[ "$(id -u)" = 0 ] || die "请用 root 运行"
command -v systemctl >/dev/null || die "需要 systemd"

uninstall() {
  systemctl disable --now sb-relay vps-relay-panel 2>/dev/null || true
  rm -f /etc/systemd/system/sb-relay.service /etc/systemd/system/vps-relay-panel.service /usr/local/bin/vps-relay
  systemctl daemon-reload
  rm -rf "$OPT"
  read -rp "同时删除节点密钥和配置 $ETC ？[y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] && rm -rf "$ETC"
  green "已卸载"
}
[ "${1:-}" = "uninstall" ] && { uninstall; exit 0; }

install_deps() {
  local need=()
  for c in curl tar openssl python3 socat crontab; do command -v "$c" >/dev/null || need+=("$c"); done
  [ ${#need[@]} -eq 0 ] && return
  echo "安装依赖: ${need[*]}"
  if command -v apt-get >/dev/null; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl tar openssl python3 ca-certificates socat cron
  elif command -v dnf >/dev/null; then
    dnf install -y -q curl tar openssl python3 ca-certificates socat cronie
  elif command -v yum >/dev/null; then
    yum install -y -q curl tar openssl python3 ca-certificates socat cronie
  else
    die "不认识的系统，请手动安装: ${need[*]}"
  fi
}

install_singbox() {
  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "不支持的架构 $(uname -m)" ;;
  esac
  if [ -x "$OPT/bin/sing-box" ] && "$OPT/bin/sing-box" version | grep -q "version $SB_VERSION\$"; then
    return
  fi
  echo "下载 sing-box $SB_VERSION ($arch)"
  local tmp; tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/sb.tgz" \
    "https://github.com/SagerNet/sing-box/releases/download/v$SB_VERSION/sing-box-$SB_VERSION-linux-$arch.tar.gz"
  tar xzf "$tmp/sb.tgz" -C "$tmp"
  install -Dm755 "$tmp/sing-box-$SB_VERSION-linux-$arch/sing-box" "$OPT/bin/sing-box"
  rm -rf "$tmp"
}

install_code() {
  local src; src="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
  mkdir -p "$OPT/panel"
  if [ -n "$src" ] && [ -f "$src/panel/app.py" ]; then
    cp "$src/panel/app.py" "$src/panel/index.html" "$OPT/panel/"
  else
    echo "下载面板代码 $REPO@$BRANCH"
    local tmp; tmp=$(mktemp -d)
    curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH" | tar xz -C "$tmp" --strip-components=1
    cp "$tmp/panel/app.py" "$tmp/panel/index.html" "$OPT/panel/"
    rm -rf "$tmp"
  fi
  cat > /usr/local/bin/vps-relay <<EOF
#!/bin/sh
exec python3 $OPT/panel/app.py "\$@"
EOF
  chmod 755 /usr/local/bin/vps-relay
}

install_services() {
  cat > /etc/systemd/system/sb-relay.service <<EOF
[Unit]
Description=sing-box (vps-relay)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$OPT/bin/sing-box run -c $ETC/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/vps-relay-panel.service <<EOF
[Unit]
Description=vps-relay 管理面板
After=network-online.target sb-relay.service

[Service]
ExecStart=/usr/bin/env python3 $OPT/panel/app.py serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable sb-relay vps-relay-panel >/dev/null 2>&1
  systemctl restart sb-relay vps-relay-panel
}

open_firewall() {
  local ports
  ports=$(python3 -c "
import json; s=json.load(open('$ETC/state.json'))
print(s['panel']['port'], s['inbounds']['vless']['port'], s['inbounds']['smart']['port'], s['inbounds']['hy2']['port'])")
  set -- $ports
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "$1/tcp" >/dev/null; ufw allow "$2/tcp" >/dev/null; ufw allow "$3/tcp" >/dev/null; ufw allow "$4/udp" >/dev/null
    ufw allow 80/tcp >/dev/null  # 申请/续期证书用
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd -q --permanent --add-port="$1/tcp" --add-port="$2/tcp" --add-port="$3/tcp" --add-port="$4/udp" --add-port=80/tcp
    firewall-cmd -q --reload
  fi
}

enable_bbr() {
  [ "${ENABLE_BBR:-1}" = 1 ] || return 0
  sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr && return 0
  modprobe tcp_bbr 2>/dev/null || true
  cat > /etc/sysctl.d/99-vps-relay-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl -q --system || true
}

install_deps
install_singbox
install_code
if [ ! -f "$ETC/state.json" ]; then
  VPS_RELAY_ETC="$ETC" VPS_RELAY_OPT="$OPT" python3 "$OPT/panel/app.py" init
else
  echo "检测到已有配置，保留节点和规则，只升级程序"
  python3 "$OPT/panel/app.py" apply >/dev/null || true
fi
install_services
open_firewall
enable_bbr

sleep 2
systemctl is-active -q sb-relay || { journalctl -u sb-relay -n 30 --no-pager; die "sing-box 启动失败"; }
systemctl is-active -q vps-relay-panel || { journalctl -u vps-relay-panel -n 30 --no-pager; die "面板启动失败"; }
if [ -n "${DOMAIN:-}" ]; then
  vps-relay set-domain "$DOMAIN" || red "域名证书没有申请成功，面板暂时用 IP 访问。解决后运行: vps-relay set-domain $DOMAIN"
fi
green "安装完成"
echo
vps-relay info
echo
grep -q '"domain": "' "$ETC/state.json" || echo "面板目前用自签名证书。想去掉浏览器警告，把域名解析到本机后运行: vps-relay set-domain 你的域名"
echo "如果服务商有安全组/防火墙，请放行上面的面板端口(TCP)、两个 VLESS 端口(TCP)和 Hysteria2 端口(UDP)。"
echo "常用命令: vps-relay info | vps-relay reset-password | vps-relay set-domain 域名 | systemctl restart sb-relay"
