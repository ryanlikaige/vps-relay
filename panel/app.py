#!/usr/bin/env python3
"""vps-relay 管理面板与命令行工具（仅依赖 Python 3 标准库）。

用法:
  app.py init            首次安装时生成节点密钥、端口和面板密码
  app.py serve           运行管理面板
  app.py apply           按 state.json 重新生成 sing-box 配置并重启
  app.py info            显示面板地址和节点链接
  app.py reset-password  重置面板密码
  app.py set-upstream <分享链接或IP:端口:用户:密码>  设置静态 ISP / B 机出口
  app.py set-domain <域名>       给面板和 Hysteria2 申请正式证书
"""
import base64
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

ETC = os.environ.get("VPS_RELAY_ETC", "/etc/vps-relay")
OPT = os.environ.get("VPS_RELAY_OPT", "/opt/vps-relay")
STATE = os.path.join(ETC, "state.json")
CONFIG = os.path.join(ETC, "config.json")
RULES = os.path.join(ETC, "rules.json")
BACKUPS = os.path.join(ETC, "backups")
SINGBOX = os.path.join(OPT, "bin", "sing-box")
INDEX_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
SERVICE = "sb-relay"

GEMINI_DOMAINS = [
    "gemini.google.com",
    "gemini.google",
    "bard.google.com",
    "aistudio.google.com",
    "makersuite.google.com",
    "ai.google.dev",
    "ai.google",
    "generativelanguage.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "robinfrontend-pa.googleapis.com",
    "alkalimakersuite-pa.clients6.google.com",
    "alkalicore-pa.clients6.google.com",
    "geller-pa.googleapis.com",
    "assistant-s3-pa.googleapis.com",
    "aisandbox-pa.googleapis.com",
    "tailwind-pa.googleapis.com",
    "waa-pa.googleapis.com",
    "notebooklm.google",
    "notebooklm.google.com",
    "labs.google",
    "labs.google.com",
    "deepmind.google",
    "deepmind.com",
    "jules.google",
    "jules.google.com",
    "opal.google",
    "opal.withgoogle.com",
    "stitch.withgoogle.com",
    "idx.google.com",
    "idx.dev",
    "firebase.studio",
]

CHATGPT_DOMAINS = [
    "openai.com",
    "chatgpt.com",
    "chat.com",
    "ai.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "sora.com",
    "openaiapi-site.azureedge.net",
    "openaicom.imgix.net",
    "auth0.com",
    "statsigapi.net",
    "statsig.com",
    "featuregates.org",
    "arkoselabs.com",
    "challenges.cloudflare.com",
    "stripe.com",
    "stripecdn.com",
]

CLAUDE_DOMAINS = [
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "claudeusercontent.com",
    "clau.de",
    "statsigapi.net",
    "statsig.com",
    "featuregates.org",
    "challenges.cloudflare.com",
    "hcaptcha.com",
    "stripe.com",
    "stripecdn.com",
]

VERIFY_IP_DOMAINS = [
    "textverified.com",
    "ipinfo.io",
    "scamalytics.com",
    "browserleaks.com",
]

CLAUDE_GPT_ALL = list(dict.fromkeys(CLAUDE_DOMAINS + CHATGPT_DOMAINS + VERIFY_IP_DOMAINS))

META_AI_DOMAINS = [
    "meta.ai",
    "meta.com",
    "ai.meta.com",
    "llama.com",
    "metademolab.com",
    "fbaipublicfiles.com",
]

META_ALL_DOMAINS = [
    "facebook.com",
    "fb.com",
    "fb.me",
    "fb.watch",
    "fb.gg",
    "fbcdn.net",
    "facebook.net",
    "fbsbx.com",
    "fbpigeon.com",
    "fbworkmail.com",
    "messenger.com",
    "m.me",
    "accountkit.com",
    "atdmt.com",
    "freebasics.com",
    "internet.org",
    "instagram.com",
    "cdninstagram.com",
    "ig.me",
    "igcdn.com",
    "igsonar.com",
    "igtv.com",
    "threads.net",
    "threads.com",
    "whatsapp.com",
    "whatsapp.net",
    "wa.me",
    "whatsappbrand.com",
    "meta.com",
    "meta.ai",
    "oculus.com",
    "oculuscdn.com",
]

GROK_DOMAINS = [
    "grok.com",
    "x.ai",
    "xai.com",
    "challenges.cloudflare.com",
    "stripe.com",
    "stripecdn.com",
]

X_ALL_DOMAINS = [
    "x.com",
    "twitter.com",
    "twimg.com",
    "t.co",
    "twttr.com",
    "twttr.net",
    "tweetdeck.com",
    "periscope.tv",
    "pscp.tv",
    "vine.co",
    "ads-twitter.com",
    "cms-twdigitalassets.com",
]

DEFAULT_SUFFIXES = GEMINI_DOMAINS
DEFAULT_KEYWORDS = []

# 一键预设：每组是一批完整域名后缀，面板里可以一键添加或删除
PRESETS = [
    {"id": "claude_gpt", "name": "Claude + ChatGPT 完整套装（静态 ISP 推荐）",
     "desc": "一键覆盖 Claude、ChatGPT 网页与 App、Auth0/Arkose 登录鉴权、CF/hCaptcha 盾牌、Stripe 支付及接码/IP 纯净度检测",
     "suffix": CLAUDE_GPT_ALL},
    {"id": "gemini", "name": "Gemini / Google AI",
     "desc": "完整覆盖 Gemini、AI Studio、NotebookLM、DeepMind、Google Labs、Jules、Opal、IDX 等（不含 YouTube）",
     "suffix": GEMINI_DOMAINS},
    {"id": "chatgpt", "name": "ChatGPT / OpenAI",
     "desc": "完整覆盖 ChatGPT 网页与 App、OpenAI API、Sora、Auth0/Arkose 登录验证、Statsig 开关及 Stripe 支付",
     "suffix": CHATGPT_DOMAINS},
    {"id": "claude", "name": "Claude / Anthropic",
     "desc": "完整覆盖 Claude 网页、桌面版与 App、Anthropic API、Artifacts 沙盒、CF/hCaptcha 验证及 Stripe 支付",
     "suffix": CLAUDE_DOMAINS},
    {"id": "meta", "name": "Meta AI",
     "desc": "完整覆盖 meta.ai 网页版、Meta 账号鉴权、Llama 官网及模型资源（不含 FB/IG 视频流）",
     "suffix": META_AI_DOMAINS},
    {"id": "meta_all", "name": "Facebook / Instagram / WhatsApp 全站",
     "desc": "完整覆盖 Meta 旗下全部网站、短链（wa.me/ig.me/m.me/fb.watch）与 CDN（含视频，流量较大）",
     "suffix": META_ALL_DOMAINS},
    {"id": "grok", "name": "Grok / xAI",
     "desc": "完整覆盖 grok.com 独立站、xAI 控制台与 API、CF 验证及 SuperGrok 支付",
     "suffix": GROK_DOMAINS},
    {"id": "x_all", "name": "X (Twitter) 全站",
     "desc": "完整覆盖 X 网页与 App、图片视频 CDN、t.co 短链、TweetDeck 及 Spaces 语音直播（流量较大）",
     "suffix": X_ALL_DOMAINS},
]


def preset_status(state):
    have = set(state["rules"]["domain_suffix"])
    out = []
    for p in PRESETS:
        n = sum(1 for d in p["suffix"] if d in have)
        status = "on" if n == len(p["suffix"]) else ("partial" if n else "off")
        out.append({"id": p["id"], "name": p["name"], "desc": p["desc"], "domains": p["suffix"], "status": status})
    return out


lock = threading.Lock()


# ---------------------------------------------------------------- 存储

def load_state():
    with open(STATE) as f:
        state = json.load(f)
    ib = state["inbounds"]
    if "smart_hy2" not in ib:
        used = {n["port"] for n in ib.values()} | {state["panel"]["port"]} | set(state["probe"].values())
        ib["smart_hy2"] = {"port": pick_port("SMART_HY2_PORT", used), "password": secrets.token_urlsafe(16)}
        save_state(state)
    return state


def write_json(path, data, mode=0o600):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def save_state(state):
    write_json(STATE, state)


def backup(path):
    if not os.path.exists(path):
        return
    os.makedirs(BACKUPS, exist_ok=True)
    name = "%s.%s" % (os.path.basename(path), time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, os.path.join(BACKUPS, name))
    olds = sorted(f for f in os.listdir(BACKUPS) if f.startswith(os.path.basename(path) + "."))
    for f in olds[:-20]:
        os.remove(os.path.join(BACKUPS, f))


def run(cmd, timeout=30):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


# ---------------------------------------------------------------- 分享链接与静态 ISP 解析

def _q(params, *names, default=""):
    for n in names:
        v = params.get(n)
        if v:
            return v[0]
    return default


def _truthy(v):
    return str(v).lower() in ("1", "true", "yes")


def _transport(net, host, path, service_name):
    if net == "ws":
        t = {"type": "ws", "path": path or "/"}
        m = re.search(r"[?&]ed=(\d+)", path or "")
        if m:
            t["path"] = re.sub(r"[?&]ed=\d+", "", path) or "/"
            t["max_early_data"] = int(m.group(1))
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if host:
            t["headers"] = {"Host": host}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": service_name or path or ""}
    if net in ("http", "h2"):
        t = {"type": "http", "path": path or "/"}
        if host:
            t["host"] = [host]
        return t
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": path or "/"}
        if host:
            t["host"] = host
        return t
    return None


def _parse_bare_proxy(raw):
    """解析 Proxy-Seller 常见的 IP:端口:用户名:密码 / IP:端口 / 用户名:密码@IP:端口 格式（默认 SOCKS5）。"""
    clean = raw.split("#", 1)[0].strip()
    if "@" in clean:
        return parse_link("socks5://" + clean)
    m6 = re.match(r"^\[([^\]]+)\]:(\d+)(?::([^:]*):(.*))?$", clean)
    if m6:
        host, port, user, pw = m6.group(1), int(m6.group(2)), m6.group(3), m6.group(4)
        if not (1 <= port <= 65535):
            raise ValueError("端口超出范围")
        ob = {"type": "socks", "server": host, "server_port": port, "version": "5"}
        if user:
            ob["username"] = user
        if pw is not None and pw != "":
            ob["password"] = pw
        return ob
    parts = clean.split(":", 3)
    if len(parts) == 2 and parts[1].isdigit():
        port = int(parts[1])
        if not parts[0] or not (1 <= port <= 65535):
            raise ValueError("地址或端口格式不对")
        return {"type": "socks", "server": parts[0].strip(), "server_port": port, "version": "5"}
    if len(parts) == 4 and parts[1].isdigit():
        port = int(parts[1])
        if not parts[0] or not (1 <= port <= 65535):
            raise ValueError("地址或端口格式不对")
        ob = {"type": "socks", "server": parts[0].strip(), "server_port": port, "version": "5"}
        if parts[2]:
            ob["username"] = parts[2]
        if parts[3]:
            ob["password"] = parts[3]
        return ob
    raise ValueError("无法识别的代理格式，请填写 IP:端口:用户名:密码 或 socks5:// / vless:// 链接")


def parse_link(link):
    """把静态 ISP 代理（SOCKS5/HTTP）或 B 机分享链接转成 sing-box 出站配置。"""
    link = link.strip()
    if not link:
        raise ValueError("请输入代理参数或节点链接")
    if "://" not in link:
        return _parse_bare_proxy(link)

    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        raw = link[8:].split("#", 1)[0]
        raw += "=" * (-len(raw) % 4)
        j = json.loads(base64.b64decode(raw).decode())
        ob = {
            "type": "vmess",
            "server": j["add"],
            "server_port": int(j["port"]),
            "uuid": j["id"],
            "security": j.get("scy") or "auto",
            "alter_id": int(j.get("aid") or 0),
        }
        if j.get("tls") == "tls":
            ob["tls"] = {"enabled": True, "server_name": j.get("sni") or j.get("host") or j["add"]}
            if _truthy(j.get("allowInsecure", "")):
                ob["tls"]["insecure"] = True
        t = _transport(j.get("net", "tcp"), j.get("host", ""), j.get("path", ""), j.get("path", ""))
        if t:
            ob["transport"] = t
        return ob

    u = urllib.parse.urlsplit(link)
    p = urllib.parse.parse_qs(u.query)
    host, port = u.hostname, u.port
    if not host or not port:
        raise ValueError("链接里缺少地址或端口")
    user = urllib.parse.unquote(u.username or "")
    pw = urllib.parse.unquote(u.password or "") if u.password is not None else None
    insecure = _truthy(_q(p, "insecure", "allowInsecure", "allow_insecure"))
    sni = _q(p, "sni", "peer", default="")

    if scheme in ("socks", "socks5", "socks5h"):
        ob = {"type": "socks", "server": host, "server_port": port, "version": "5"}
        if user:
            ob["username"] = user
        if pw is not None:
            ob["password"] = pw
        return ob

    if scheme in ("http", "https"):
        ob = {"type": "http", "server": host, "server_port": port}
        if user:
            ob["username"] = user
        if pw is not None:
            ob["password"] = pw
        if scheme == "https":
            tls = {"enabled": True, "server_name": sni or host}
            if insecure:
                tls["insecure"] = True
            ob["tls"] = tls
        return ob

    if scheme == "vless" or scheme == "trojan":
        ob = {"type": scheme, "server": host, "server_port": port}
        if scheme == "vless":
            ob["uuid"] = user
            flow = _q(p, "flow")
            if flow:
                ob["flow"] = flow
            ob["packet_encoding"] = "xudp"
        else:
            ob["password"] = user
        security = _q(p, "security", default="tls" if scheme == "trojan" else "none")
        if security in ("tls", "reality"):
            tls = {"enabled": True, "server_name": sni or host}
            if insecure:
                tls["insecure"] = True
            fp = _q(p, "fp")
            if fp or security == "reality":
                tls["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
            alpn = _q(p, "alpn")
            if alpn:
                tls["alpn"] = alpn.split(",")
            if security == "reality":
                tls["reality"] = {"enabled": True, "public_key": _q(p, "pbk"), "short_id": _q(p, "sid")}
            ob["tls"] = tls
        t = _transport(_q(p, "type", default="tcp"), _q(p, "host"), _q(p, "path"), _q(p, "serviceName"))
        if t:
            ob["transport"] = t
        return ob

    if scheme in ("hysteria2", "hy2"):
        ob = {
            "type": "hysteria2",
            "server": host,
            "server_port": port,
            "password": user if pw is None else "%s:%s" % (user, pw),
            "tls": {"enabled": True, "server_name": sni or host, "alpn": ["h3"]},
        }
        if insecure:
            ob["tls"]["insecure"] = True
        if _q(p, "obfs"):
            ob["obfs"] = {"type": _q(p, "obfs"), "password": _q(p, "obfs-password")}
        return ob

    if scheme == "tuic":
        ob = {
            "type": "tuic",
            "server": host,
            "server_port": port,
            "uuid": user,
            "password": pw or "",
            "congestion_control": _q(p, "congestion_control", default="bbr"),
            "tls": {"enabled": True, "server_name": sni or host,
                    "alpn": (_q(p, "alpn", default="h3")).split(",")},
        }
        if insecure:
            ob["tls"]["insecure"] = True
        return ob

    if scheme == "anytls":
        ob = {"type": "anytls", "server": host, "server_port": port, "password": user,
              "tls": {"enabled": True, "server_name": sni or host}}
        if insecure:
            ob["tls"]["insecure"] = True
        return ob

    if scheme == "ss":
        if pw is None:
            raw = user + "=" * (-len(user) % 4)
            method, password = base64.urlsafe_b64decode(raw).decode().split(":", 1)
        else:
            method, password = user, pw
        return {"type": "shadowsocks", "server": host, "server_port": port,
                "method": method, "password": password}

    raise ValueError("不支持的链接类型: %s" % scheme)


# ---------------------------------------------------------------- 配置生成

def link_name(state, suffix):
    return urllib.parse.quote("%s-%s" % (state.get("name", "A"), suffix))


def host_for_link(ip):
    try:
        if ipaddress.ip_address(ip).version == 6:
            return "[%s]" % ip
    except ValueError:
        pass
    return ip


def node_links(state):
    ib = state["inbounds"]
    h = host_for_link(state["server_ip"])
    v = ib["vless"]
    vless = ("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality"
             "&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s") % (
        v["uuid"], h, v["port"], v["sni"], v["public_key"], v["short_id"], link_name(state, "reality"))

    def hy2_link(node, suffix):
        if state.get("domain"):
            return "hysteria2://%s@%s:%d?sni=%s&alpn=h3#%s" % (
                urllib.parse.quote(node["password"]), h, node["port"], state["domain"], link_name(state, suffix))
        return "hysteria2://%s@%s:%d?sni=%s&alpn=h3&insecure=1#%s" % (
            urllib.parse.quote(node["password"]), h, node["port"], ib["hy2"]["sni"], link_name(state, suffix))

    hy2 = hy2_link(ib["hy2"], "hy2")
    smart_hy2 = hy2_link(ib["smart_hy2"], "smart-hy2")
    m = ib["smart"]
    smart = ("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality"
             "&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s") % (
        m["uuid"], h, m["port"], v["sni"], v["public_key"], m["short_id"], link_name(state, "smart"))
    return {"vless": vless, "hy2": hy2, "smart": smart, "smart_hy2": smart_hy2}


def build_rules(state):
    rule = {}
    if state["rules"]["domain_suffix"]:
        rule["domain_suffix"] = state["rules"]["domain_suffix"]
    if state["rules"]["domain_keyword"]:
        rule["domain_keyword"] = state["rules"]["domain_keyword"]
    if not rule:
        rule["domain"] = ["placeholder.invalid"]
    return {"version": 3, "rules": [rule]}


def cert_paths(state, fallback):
    """有域名时用 Let's Encrypt 证书，否则用自签名证书。"""
    name = "domain" if state.get("domain") and os.path.exists(os.path.join(ETC, "domain.crt")) else fallback
    return os.path.join(ETC, name + ".crt"), os.path.join(ETC, name + ".key")


def panel_url(state):
    host = state.get("domain") or host_for_link(state["server_ip"])
    return "https://%s:%d%s/" % (host, state["panel"]["port"], state["panel"]["path"])


def hy2_inbound(tag, state, node):
    return {
        "type": "hysteria2", "tag": tag, "listen": "::", "listen_port": node["port"],
        "users": [{"password": node["password"]}],
        "tls": {"enabled": True, "alpn": ["h3"],
                "certificate_path": cert_paths(state, "hy2")[0],
                "key_path": cert_paths(state, "hy2")[1]},
    }


def reality_inbound(tag, ib, node):
    return {
        "type": "vless", "tag": tag, "listen": "::", "listen_port": node["port"],
        "users": [{"uuid": node["uuid"], "flow": "xtls-rprx-vision"}],
        "tls": {
            "enabled": True, "server_name": ib["vless"]["sni"],
            "reality": {
                "enabled": True,
                "handshake": {"server": ib["vless"]["sni"], "server_port": 443},
                "private_key": ib["vless"]["private_key"],
                "short_id": [node["short_id"]],
            },
        },
    }


def build_config(state):
    ib = state["inbounds"]
    up = state.get("upstream")
    to_b = dict(up["outbound"]) if up else {"type": "direct"}
    to_b["tag"] = "to-b"
    route_rules = [
        {"action": "sniff"},
        {"inbound": ["probe-b"], "outbound": "to-b"},
    ]
    # 静态 ISP (SOCKS5 / HTTP) 不支持 UDP 转发，阻断命中分流规则的 QUIC (UDP 443)，让浏览器秒切 TCP TLS 1.3
    if to_b.get("type") in ("socks", "http"):
        route_rules.append({
            "inbound": ["smart-in", "smart-hy2-in", "probe-smart"],
            "rule_set": ["via-b"],
            "network": "udp",
            "port": 443,
            "action": "reject",
        })
    route_rules.append({
        "inbound": ["smart-in", "smart-hy2-in", "probe-smart"],
        "rule_set": ["via-b"],
        "outbound": "to-b",
    })
    return {
        "log": {"level": "info" if state.get("debug_log") else "warn", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": [
            hy2_inbound("hy2-in", state, ib["hy2"]),
            reality_inbound("vless-in", ib, ib["vless"]),
            reality_inbound("smart-in", ib, ib["smart"]),
            hy2_inbound("smart-hy2-in", state, ib["smart_hy2"]),
            {"type": "mixed", "tag": "probe-b", "listen": "127.0.0.1", "listen_port": state["probe"]["b"]},
            {"type": "mixed", "tag": "probe-smart", "listen": "127.0.0.1", "listen_port": state["probe"]["smart"]},
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}, to_b],
        "route": {
            "rule_set": [{"type": "local", "tag": "via-b", "format": "source", "path": RULES}],
            "rules": route_rules,
            "final": "direct",
            "default_domain_resolver": "local",
        },
    }


def check_config(cfg):
    tmp = CONFIG + ".check"
    write_json(tmp, cfg)
    code, out = run([SINGBOX, "check", "-c", tmp])
    os.remove(tmp)
    return code == 0, out


def write_rules(state):
    write_json(RULES, build_rules(state), 0o644)


def apply_config(state):
    """检查并写入配置后重启 sing-box；失败时回滚到上一份配置。"""
    cfg = build_config(state)
    write_rules(state)
    ok, out = check_config(cfg)
    if not ok:
        return False, "配置检查失败: " + out
    backup(CONFIG)
    old = open(CONFIG).read() if os.path.exists(CONFIG) else None
    write_json(CONFIG, cfg)
    code, out = run(["systemctl", "restart", SERVICE])
    time.sleep(1.5)
    if code != 0 or not service_active():
        if old is not None:
            with open(CONFIG, "w") as f:
                f.write(old)
            run(["systemctl", "restart", SERVICE])
        return False, "重启失败，已回滚: " + (out or journal(20))
    return True, "已生效"


ROUTED_RE = re.compile(r"outbound/(\w+)\[([\w-]+)\]: outbound connection to (\S+)")


def routed_domains(lines=5000):
    """统计日志里各目标域名走了哪个出口（需要先开启诊断日志）。"""
    code, out = run(["journalctl", "-u", SERVICE, "-n", str(lines), "--no-pager", "-o", "cat"])
    seen = {}
    for m in ROUTED_RE.finditer(re.sub(r"\x1b\[[0-9;]*m", "", out)):
        host = m.group(3).rsplit(":", 1)[0]
        via = "ISP/B出口" if m.group(2) == "to-b" else "A直连"
        seen[(host, via)] = seen.get((host, via), 0) + 1
    rows = [{"host": h, "via": v, "count": c} for (h, v), c in seen.items()]
    rows.sort(key=lambda r: (r["via"] != "ISP/B出口", -r["count"]))
    return rows[:300]


SYSTEMD_DIR = os.environ.get("VPS_RELAY_SYSTEMD", "/etc/systemd/system")
REBOOT_TIMER = "vps-relay-reboot.timer"
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def reboot_units(hhmm):
    service = """[Unit]
Description=vps-relay 定时重启 VPS

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'sync; exec /bin/systemctl reboot'
"""
    timer = """[Unit]
Description=vps-relay 每日定时重启

[Timer]
OnCalendar=*-*-* %s:00
Persistent=false
AccuracySec=1s

[Install]
WantedBy=timers.target
""" % hhmm
    return service, timer


def apply_reboot_schedule(cfg):
    if cfg.get("enabled"):
        if not TIME_RE.match(str(cfg.get("time", ""))):
            raise ValueError("时间格式应为 HH:MM，例如 04:30")
        service, timer = reboot_units(cfg["time"])
        with open(os.path.join(SYSTEMD_DIR, "vps-relay-reboot.service"), "w") as f:
            f.write(service)
        with open(os.path.join(SYSTEMD_DIR, REBOOT_TIMER), "w") as f:
            f.write(timer)
        run(["systemctl", "daemon-reload"])
        code, out = run(["systemctl", "enable", "--now", REBOOT_TIMER])
        if code != 0:
            raise ValueError("启用定时器失败: " + out)
        run(["systemctl", "restart", REBOOT_TIMER])
    else:
        run(["systemctl", "disable", "--now", REBOOT_TIMER])


def reboot_info(state):
    cfg = state.get("reboot") or {"enabled": False, "time": "04:00"}
    info = {"enabled": bool(cfg.get("enabled")), "time": cfg.get("time", "04:00")}
    info["now"] = time.strftime("%Y-%m-%d %H:%M:%S")
    info["tz"] = time.strftime("%Z %z")
    try:
        info["booted_at"] = time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(time.time() - float(open("/proc/uptime").read().split()[0])))
    except OSError:
        pass
    if info["enabled"]:
        code, out = run(["systemctl", "show", REBOOT_TIMER, "-p", "NextElapseUSecRealtime", "--value"])
        info["next"] = out.strip() if code == 0 and out.strip() else None
        info["timer_active"] = run(["systemctl", "is-active", REBOOT_TIMER])[1].strip() == "active"
    info["boot_check"] = state.get("boot_check")
    return info


def tcp_listening(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return True
    except OSError:
        return False


def post_boot_check():
    """开机后自检：确认 sing-box 在运行且节点端口在监听，不正常就重启它一次。"""
    try:
        if float(open("/proc/uptime").read().split()[0]) > 600:
            return
    except OSError:
        return
    time.sleep(25)
    for attempt in (1, 2):
        state = load_state()
        ib = state["inbounds"]
        ok = service_active() and all(tcp_listening(ib[k]["port"]) for k in ("vless", "smart"))
        if ok or attempt == 2:
            break
        run(["systemctl", "restart", SERVICE])
        time.sleep(10)
    with lock:
        state = load_state()
        state["boot_check"] = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "ok": ok, "restarted": attempt == 2 or (not ok)}
        save_state(state)


def service_active(name=SERVICE):
    code, out = run(["systemctl", "is-active", name])
    return out.strip() == "active"


def journal(lines=100):
    code, out = run(["journalctl", "-u", SERVICE, "-n", str(lines), "--no-pager", "-o", "short-iso"])
    return out


# ---------------------------------------------------------------- 状态与测试

def system_status():
    st = {"service": service_active()}
    try:
        st["uptime"] = float(open("/proc/uptime").read().split()[0])
        st["load"] = open("/proc/loadavg").read().split()[:3]
        mem = {}
        for line in open("/proc/meminfo"):
            k, v = line.split(":", 1)
            mem[k] = int(v.split()[0])
        st["mem_total"] = mem["MemTotal"] // 1024
        st["mem_used"] = (mem["MemTotal"] - mem.get("MemAvailable", 0)) // 1024
    except OSError:
        pass
    return st


def tcp_latency(host, port, count=3):
    res = []
    for _ in range(count):
        t = time.time()
        try:
            with socket.create_connection((host, port), timeout=3):
                res.append(round((time.time() - t) * 1000, 1))
        except OSError:
            res.append(None)
    return res


def upstream_status(state):
    up = state.get("upstream")
    if not up:
        return {"configured": False}
    ob = up["outbound"]
    t_label = {
        "socks": "SOCKS5 静态 ISP",
        "http": "HTTP 静态 ISP",
    }.get(ob["type"], ob["type"])
    r = {
        "configured": True,
        "type": t_label,
        "raw_type": ob["type"],
        "server": ob["server"],
        "port": ob["server_port"],
        "has_auth": bool(ob.get("username")),
    }
    if ob["type"] in ("hysteria2", "tuic"):
        r["latency"] = None
        r["note"] = "UDP 协议无法用 TCP 测延迟，请用下面的出口测试"
    else:
        r["latency"] = tcp_latency(ob["server"], ob["server_port"])
    return r


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _opener(proxy_port):
    if proxy_port:
        proxy = "http://127.0.0.1:%d" % proxy_port
        return urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _fetch(opener, url, timeout=12):
    t = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(200000)
            return {"status": r.status, "url": r.geturl(), "ms": round((time.time() - t) * 1000), "body": body}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "url": url, "ms": round((time.time() - t) * 1000), "body": b""}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "ms": round((time.time() - t) * 1000)}


def exit_test(state, via):
    port = {"direct": None, "b": state["probe"]["b"], "smart": state["probe"]["smart"]}[via]
    op = _opener(port)
    out = {"via": via}
    r = _fetch(op, "https://ipinfo.io/json")
    if "error" in r:
        out["ip_error"] = r["error"]
    else:
        try:
            j = json.loads(r["body"])
            out.update(
                ip=j.get("ip"),
                country=j.get("country"),
                region=j.get("region"),
                city=j.get("city"),
                org=j.get("org"),
                timezone=j.get("timezone"),
            )
        except ValueError:
            out["ip_error"] = "HTTP %s" % r.get("status")
    for key, test_url in (
        ("claude", "https://claude.ai"),
        ("chatgpt", "https://chatgpt.com"),
        ("gemini", "https://gemini.google.com/app"),
    ):
        res = _fetch(op, test_url)
        res.pop("body", None)
        out[key] = res
    return out


# ---------------------------------------------------------------- 面板认证

def hash_password(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000).hex()
    return salt, h


def check_password(state, pw):
    salt, h = hash_password(pw, state["panel"]["salt"])
    return hmac.compare_digest(h, state["panel"]["password_hash"])


def remove_initial_password():
    try:
        os.remove(os.path.join(ETC, ".initial-password"))
    except FileNotFoundError:
        pass


def make_token(state, days=7):
    exp = str(int(time.time()) + days * 86400)
    sig = hmac.new(bytes.fromhex(state["panel"]["secret"]), exp.encode(), "sha256").hexdigest()
    return exp + "." + sig


def valid_token(state, token):
    try:
        exp, sig = token.split(".", 1)
        good = hmac.new(bytes.fromhex(state["panel"]["secret"]), exp.encode(), "sha256").hexdigest()
        return hmac.compare_digest(sig, good) and int(exp) > time.time()
    except (ValueError, AttributeError):
        return False


login_fails = {}


def login_blocked(ip):
    fails = [t for t in login_fails.get(ip, []) if t > time.time() - 600]
    login_fails[ip] = fails
    return len(fails) >= 5


DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


def clean_list(items, pattern=DOMAIN_RE):
    out = []
    for it in items:
        it = str(it).strip().lower()
        it = re.sub(r"^https?://", "", it).split("/", 1)[0].lstrip(".")
        if not it:
            continue
        if not pattern.match(it):
            raise ValueError("格式不对: %s" % it)
        if it not in out:
            out.append(it)
    return out


# ---------------------------------------------------------------- HTTP 服务

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _route(self):
        state = load_state()
        base = state["panel"]["path"]
        path = urllib.parse.urlsplit(self.path).path
        if path == base:
            self._send(301, "", headers={"Location": base + "/"})
            return None, None, None
        if not path.startswith(base + "/"):
            self._send(404, "404 Not Found", "text/plain")
            return None, None, None
        return state, path[len(base):], self._authed(state)

    def _authed(self, state):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "vr_session" and valid_token(state, v):
                return True
        return False

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 100000:
            raise ValueError("请求太大")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        state, sub, authed = self._route()
        if state is None:
            return
        if sub == "/":
            with open(INDEX_HTML, "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
            return
        if not authed:
            self._send(401, {"error": "未登录"})
            return
        if sub == "/api/state":
            up = state.get("upstream")
            self._send(200, {
                "name": state.get("name", "A"),
                "server_ip": state["server_ip"],
                "rules": state["rules"],
                "presets": preset_status(state),
                "upstream": {
                    "link_type": up["outbound"]["type"],
                    "server": up["outbound"]["server"],
                    "port": up["outbound"]["server_port"],
                    "username": up["outbound"].get("username", ""),
                } if up else None,
                "links": node_links(state),
                "debug_log": bool(state.get("debug_log")),
                "ports": {k: state["inbounds"][k]["port"] for k in ("vless", "hy2", "smart", "smart_hy2")},
            })
        elif sub == "/api/status":
            self._send(200, {"a": system_status(), "b": upstream_status(state)})
        elif sub == "/api/reboot":
            self._send(200, reboot_info(state))
        elif sub == "/api/logs":
            self._send(200, {"logs": journal(200)})
        elif sub == "/api/routed":
            self._send(200, {"rows": routed_domains(), "debug_log": bool(state.get("debug_log"))})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        state, sub, authed = self._route()
        if state is None:
            return
        try:
            data = self._body()
        except ValueError as e:
            self._send(400, {"error": str(e)})
            return
        ip = self.client_address[0]
        if sub == "/api/login":
            if login_blocked(ip):
                self._send(429, {"error": "失败次数太多，请 10 分钟后再试"})
            elif check_password(state, str(data.get("password", ""))):
                login_fails.pop(ip, None)
                self._send(200, {"ok": True}, headers={
                    "Set-Cookie": "vr_session=%s; Path=%s/; Max-Age=604800; HttpOnly; Secure; SameSite=Strict"
                                  % (make_token(state), state["panel"]["path"])})
            else:
                login_fails.setdefault(ip, []).append(time.time())
                self._send(403, {"error": "密码错误"})
            return
        if not authed:
            self._send(401, {"error": "未登录"})
            return
        try:
            if sub == "/api/logout":
                self._send(200, {"ok": True}, headers={
                    "Set-Cookie": "vr_session=; Path=%s/; Max-Age=0" % state["panel"]["path"]})
            elif sub == "/api/rules":
                with lock:
                    state = load_state()
                    state["rules"] = {
                        "domain_suffix": clean_list(data.get("domain_suffix", [])),
                        "domain_keyword": clean_list(data.get("domain_keyword", []), re.compile(r"^[a-z0-9.-]+$")),
                    }
                    backup(RULES)
                    save_state(state)
                    write_rules(state)
                self._send(200, {"ok": True, "rules": state["rules"], "presets": preset_status(state)})
            elif sub == "/api/preset":
                preset = next((p for p in PRESETS if p["id"] == data.get("id")), None)
                if preset is None or data.get("action") not in ("add", "remove"):
                    raise ValueError("参数错误")
                with lock:
                    state = load_state()
                    cur = state["rules"]["domain_suffix"]
                    if data["action"] == "add":
                        state["rules"]["domain_suffix"] = cur + [d for d in preset["suffix"] if d not in cur]
                    else:
                        state["rules"]["domain_suffix"] = [d for d in cur if d not in preset["suffix"]]
                    backup(RULES)
                    save_state(state)
                    write_rules(state)
                self._send(200, {"ok": True, "rules": state["rules"], "presets": preset_status(state)})
            elif sub == "/api/rules/reset":
                with lock:
                    state = load_state()
                    state["rules"] = {"domain_suffix": [], "domain_keyword": []}
                    save_state(state)
                    write_rules(state)
                self._send(200, {"ok": True, "rules": state["rules"], "presets": preset_status(state)})
            elif sub == "/api/upstream":
                with lock:
                    state = load_state()
                    outbound = parse_link(str(data.get("link", "")))
                    old = state.get("upstream")
                    state["upstream"] = {"outbound": outbound}
                    ok, msg = apply_config(state)
                    if ok:
                        save_state(state)
                    else:
                        state["upstream"] = old
                self._send(200 if ok else 400, {"ok": ok, "message": msg} if ok else {"error": msg})
            elif sub == "/api/test":
                via = data.get("via")
                if via not in ("direct", "b", "smart"):
                    raise ValueError("via 参数错误")
                self._send(200, exit_test(state, via))
            elif sub == "/api/debug":
                with lock:
                    state = load_state()
                    state["debug_log"] = bool(data.get("on"))
                    ok, msg = apply_config(state)
                    if ok:
                        save_state(state)
                self._send(200 if ok else 500, {"ok": ok, "message": msg, "debug_log": state["debug_log"]} if ok else {"error": msg})
            elif sub == "/api/reboot":
                cfg = {"enabled": bool(data.get("enabled")), "time": str(data.get("time", "04:00"))}
                with lock:
                    state = load_state()
                    apply_reboot_schedule(cfg)
                    state["reboot"] = cfg
                    save_state(state)
                self._send(200, reboot_info(state))
            elif sub == "/api/reboot-now":
                if data.get("confirm") != "reboot":
                    raise ValueError("缺少确认参数")
                threading.Timer(3, lambda: run(["systemctl", "reboot"])).start()
                self._send(200, {"ok": True, "message": "3 秒后重启，面板会暂时打不开，大约 1 到 2 分钟后恢复"})
            elif sub == "/api/restart":
                with lock:
                    ok, msg = apply_config(load_state())
                self._send(200 if ok else 500, {"ok": ok, "message": msg} if ok else {"error": msg})
            elif sub == "/api/password":
                if not check_password(state, str(data.get("old", ""))):
                    raise ValueError("原密码错误")
                new = str(data.get("new", ""))
                if len(new) < 8:
                    raise ValueError("新密码至少 8 位")
                with lock:
                    state = load_state()
                    state["panel"]["salt"], state["panel"]["password_hash"] = hash_password(new)
                    state["panel"]["secret"] = secrets.token_hex(32)
                    save_state(state)
                    remove_initial_password()
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not found"})
        except (ValueError, KeyError) as e:
            self._send(400, {"error": str(e)})


def serve():
    state = load_state()
    if socket.has_ipv6:
        class Server(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6
        try:
            srv = Server(("::", state["panel"]["port"]), Handler)
        except OSError:
            srv = http.server.ThreadingHTTPServer(("0.0.0.0", state["panel"]["port"]), Handler)
    else:
        srv = http.server.ThreadingHTTPServer(("0.0.0.0", state["panel"]["port"]), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*cert_paths(state, "panel"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=post_boot_check, daemon=True).start()
    srv.serve_forever()


# ---------------------------------------------------------------- 命令行

def port_free(port):
    for fam, typ in ((socket.AF_INET, socket.SOCK_STREAM), (socket.AF_INET, socket.SOCK_DGRAM)):
        s = socket.socket(fam, typ)
        try:
            s.bind(("0.0.0.0", port))
        except OSError:
            return False
        finally:
            s.close()
    return True


def pick_port(env, used):
    if os.environ.get(env):
        return int(os.environ[env])
    while True:
        p = secrets.randbelow(40000) + 20000
        if p not in used and port_free(p):
            used.add(p)
            return p


def self_signed(name, cn):
    run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-days", "3650", "-subj", "/CN=" + cn,
         "-keyout", os.path.join(ETC, name + ".key"), "-out", os.path.join(ETC, name + ".crt")])
    os.chmod(os.path.join(ETC, name + ".key"), 0o600)


def detect_ip():
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                ipaddress.ip_address(ip)
                return ip
        except Exception:  # noqa: BLE001
            continue
    raise SystemExit("无法检测公网 IP，请用 SERVER_IP=1.2.3.4 指定")


def cmd_init():
    if os.path.exists(STATE):
        print("已存在 %s，跳过初始化" % STATE)
        return
    os.makedirs(ETC, exist_ok=True)
    os.chmod(ETC, 0o700)
    code, out = run([SINGBOX, "generate", "reality-keypair"])
    keys = dict(re.findall(r"(PrivateKey|PublicKey):\s*(\S+)", out))
    used = set()
    password = secrets.token_urlsafe(9)
    salt, h = hash_password(password)
    state = {
        "name": os.environ.get("NODE_NAME", "A-relay"),
        "server_ip": os.environ.get("SERVER_IP") or detect_ip(),
        "panel": {"port": pick_port("PANEL_PORT", used), "path": "/" + secrets.token_urlsafe(9),
                  "salt": salt, "password_hash": h, "secret": secrets.token_hex(32)},
        "inbounds": {
            "vless": {"port": pick_port("VLESS_PORT", used), "uuid": run([SINGBOX, "generate", "uuid"])[1],
                      "sni": os.environ.get("REALITY_SNI", "www.microsoft.com"),
                      "private_key": keys["PrivateKey"], "public_key": keys["PublicKey"],
                      "short_id": secrets.token_hex(8)},
            "smart": {"port": pick_port("SMART_PORT", used), "uuid": run([SINGBOX, "generate", "uuid"])[1],
                      "short_id": secrets.token_hex(8)},
            "hy2": {"port": pick_port("HY2_PORT", used), "password": secrets.token_urlsafe(16), "sni": "www.bing.com"},
            "smart_hy2": {"port": pick_port("SMART_HY2_PORT", used), "password": secrets.token_urlsafe(16)},
        },
        "probe": {"b": pick_port("", used), "smart": pick_port("", used)},
        "rules": {"domain_suffix": [], "domain_keyword": []},
        "upstream": None,
    }
    self_signed("hy2", "www.bing.com")
    self_signed("panel", state["server_ip"])
    if os.environ.get("B_LINK"):
        state["upstream"] = {"outbound": parse_link(os.environ["B_LINK"])}
    save_state(state)
    write_rules(state)
    write_json(CONFIG, build_config(state))
    ok, out = check_config(build_config(state))
    if not ok:
        raise SystemExit("sing-box 配置检查失败:\n" + out)
    with open(os.path.join(ETC, ".initial-password"), "w") as f:
        f.write(password)
    os.chmod(os.path.join(ETC, ".initial-password"), 0o600)


def cmd_info():
    state = load_state()
    links = node_links(state)
    print("管理面板: " + panel_url(state))
    pw_file = os.path.join(ETC, ".initial-password")
    if os.path.exists(pw_file):
        print("初始密码: %s  （在面板里改密码后此文件会被删除）" % open(pw_file).read().strip())
    print("\n节点 1  Hysteria2（A 直连）:\n%s" % links["hy2"])
    print("\n节点 2  VLESS-Reality（A 直连）:\n%s" % links["vless"])
    print("\n节点 3  智能分流 VLESS-Reality（规则内网站走静态 ISP/B，其余 A 直连）:\n%s" % links["smart"])
    print("\n节点 4  智能分流 Hysteria2（规则内网站走静态 ISP/B，其余 A 直连）:\n%s" % links["smart_hy2"])
    up = state.get("upstream")
    print("\n静态 ISP / B 机出口: %s" % ("%s %s:%s" % (up["outbound"]["type"], up["outbound"]["server"], up["outbound"]["server_port"])
                                      if up else "未设置（请在面板里填写 Proxy-Seller 参数或节点链接）"))


ACME = os.path.expanduser("~/.acme.sh/acme.sh")


def cmd_set_domain(domain):
    """用 acme.sh 申请 Let's Encrypt 证书，给面板和 Hysteria2 用，自动续期。"""
    try:
        domain = clean_list([domain])[0]
    except (ValueError, IndexError):
        raise SystemExit("域名格式不对: %s" % domain)
    state = load_state()
    try:
        ips = {a[4][0] for a in socket.getaddrinfo(domain, None, socket.AF_INET)}
    except socket.gaierror:
        ips = set()
    if state["server_ip"] not in ips:
        raise SystemExit("%s 当前解析到 %s，不是本机 %s。\n请先把域名 A 记录指向本机"
                         "（Cloudflare 请关闭小黄云，用「仅 DNS」），等几分钟再试。"
                         % (domain, ", ".join(sorted(ips)) or "（无记录）", state["server_ip"]))
    if not os.path.exists(ACME):
        print("安装 acme.sh ...")
        code, out = run(["sh", "-c", "curl -fsSL https://get.acme.sh | sh"], timeout=300)
        if code != 0:
            raise SystemExit("安装 acme.sh 失败:\n" + out)
    run([ACME, "--set-default-ca", "--server", "letsencrypt"])
    print("申请证书（需要本机 80 端口可以从外网访问）...")
    code, out = run([ACME, "--issue", "-d", domain, "--standalone", "--keylength", "ec-256"], timeout=300)
    if code not in (0, 2):
        raise SystemExit("申请证书失败:\n" + out[-2000:])
    code, out = run([ACME, "--install-cert", "-d", domain, "--ecc",
                     "--fullchain-file", os.path.join(ETC, "domain.crt"),
                     "--key-file", os.path.join(ETC, "domain.key"),
                     "--reloadcmd", "systemctl restart sb-relay vps-relay-panel"], timeout=120)
    if code != 0:
        raise SystemExit("安装证书失败:\n" + out[-2000:])
    os.chmod(os.path.join(ETC, "domain.key"), 0o600)
    state["domain"] = domain
    ok, msg = apply_config(state)
    if not ok:
        raise SystemExit(msg)
    save_state(state)
    run(["systemctl", "restart", "vps-relay-panel"])
    print("完成，证书会自动续期。")
    print("管理面板: " + panel_url(state))
    links = node_links(state)
    print("两个 Hysteria2 节点链接已更新（不再需要跳过证书验证），请在客户端重新导入:\n%s\n%s"
          % (links["hy2"], links["smart_hy2"]))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "info"
    if cmd == "serve":
        serve()
    elif cmd == "init":
        cmd_init()
    elif cmd == "apply":
        ok, msg = apply_config(load_state())
        print(msg)
        sys.exit(0 if ok else 1)
    elif cmd == "info":
        cmd_info()
    elif cmd == "reset-password":
        state = load_state()
        pw = secrets.token_urlsafe(9)
        state["panel"]["salt"], state["panel"]["password_hash"] = hash_password(pw)
        state["panel"]["secret"] = secrets.token_hex(32)
        save_state(state)
        remove_initial_password()
        print("新密码: " + pw)
    elif cmd == "set-domain" and len(sys.argv) > 2:
        cmd_set_domain(sys.argv[2])
    elif cmd == "set-upstream" and len(sys.argv) > 2:
        state = load_state()
        state["upstream"] = {"outbound": parse_link(sys.argv[2])}
        ok, msg = apply_config(state)
        if ok:
            save_state(state)
        print(msg)
        sys.exit(0 if ok else 1)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
