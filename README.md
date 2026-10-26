# vps-relay

A 机（CN2 线路）专用的 sing-box 一键安装脚本和网页管理面板。

A 机提供三个节点：

| 节点 | 协议 | 出口 |
| --- | --- | --- |
| 节点 1 | Hysteria2 (UDP) | 全部从 A 直连 |
| 节点 2 | VLESS Reality (TCP) | 全部从 A 直连 |
| 节点 3 | VLESS Reality (TCP) | **智能分流**：列表里的网站（默认是 Gemini）转到 B 机出口，其余从 A 直连 |

```
客户端 ──CN2──> A ──┬─ 普通网站 ──> 直接访问
                   └─ Gemini 等 ──> B（纯净 IP）──> 访问
```

B 机保持原样（yonggekkk 脚本的 sing-box），A 只是用 B 现有的某个节点作为出口，B 上什么都不用改。

## 安装（在 A 机上，root）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ryanlikaige/vps-relay/main/install.sh)
```

仓库是私有的话，先把仓库克隆到 A 机，再在仓库目录里运行 `bash install.sh`。

安装完成后会打印：

- 面板地址（`https://IP:端口/随机路径/`）和初始密码
- 三个节点的分享链接

然后：

1. 打开面板，在"B 机出口"里粘贴 B 机的任意一个节点分享链接（推荐 vless reality，在 B 机上运行 `sb` 查看节点信息即可拿到），保存。
2. 把三个节点的链接或二维码导入 v2rayN、小火箭、HomeProxy。
3. 在面板的"出口测试"里点"强制走 B"，确认出口 IP 是 B 机的。
4. 客户端选"智能分流"节点，打开 Gemini 实测。

如果服务商有安全组/防火墙，需要放行：面板端口(TCP)、节点 2 和节点 3 的端口(TCP)、节点 1 的端口(UDP)。脚本会自动放行 ufw/firewalld。

可选环境变量（安装前设置）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `VLESS_PORT` `SMART_PORT` `HY2_PORT` `PANEL_PORT` | 随机 | 指定端口 |
| `REALITY_SNI` | `www.microsoft.com` | Reality 伪装的网站 |
| `NODE_NAME` | `A-relay` | 节点名前缀 |
| `B_LINK` | 空 | 安装时直接设置 B 机节点链接 |
| `DOMAIN` | 空 | 安装时直接给面板申请正式证书（见下方"域名"） |
| `SB_VERSION` | `1.14.4` | sing-box 版本 |
| `ENABLE_BBR` | `1` | 设为 0 不开启 BBR |

## 面板功能

- 增删走 B 的网站（域名后缀 / 关键词），保存后几秒内生效，不用重启，客户端也不用更新
- 输入网址查看它会不会走 B
- B 机出口：粘贴分享链接即可，支持 vless / vmess / hysteria2 / tuic / anytls / trojan / ss
- A 机状态、A→B 延迟
- 出口测试：A 直连 / 强制走 B / 智能分流，显示出口 IP 和 Gemini 访问结果
- 节点链接复制和二维码、sing-box 日志、改密码

登录连续错 5 次会锁 10 分钟。

## 域名（可选）

不配域名也能用，只是面板用自签名证书，浏览器会提示不安全。配上域名后，面板和 Hysteria2 节点都改用 Let's Encrypt 正式证书，自动续期：

1. 在 DNS 里加一条 A 记录，把域名（比如 `panel.example.com`）指向 A 机 IP。用 Cloudflare 的话要关掉小黄云（选"仅 DNS"）。
2. 确认 A 机 80 端口能从外网访问（申请和续期证书要用）。
3. 运行 `vps-relay set-domain panel.example.com`，或者安装时加 `DOMAIN=panel.example.com`。

之后面板地址变成 `https://panel.example.com:端口/随机路径/`。Hysteria2 的链接会更新（不再需要跳过证书验证），需要在客户端重新导入；两个 VLESS 节点不受影响。

## 常用命令

```bash
vps-relay info              # 面板地址和节点链接
vps-relay reset-password    # 忘记面板密码
vps-relay set-upstream 'vless://...'  # 命令行设置 B 机节点
vps-relay set-domain panel.example.com  # 配置域名和正式证书
systemctl restart sb-relay  # 重启 sing-box
journalctl -u sb-relay -f   # 看日志
bash install.sh             # 再次运行即升级，节点和规则保留
bash install.sh uninstall   # 卸载
```

## 文件位置

| 路径 | 内容 |
| --- | --- |
| `/etc/vps-relay/state.json` | 所有设置（端口、密钥、规则、B 机出口），面板据此生成配置 |
| `/etc/vps-relay/config.json` | 生成的 sing-box 配置，不要手改 |
| `/etc/vps-relay/rules.json` | 智能分流规则集，sing-box 自动重新加载 |
| `/etc/vps-relay/backups/` | 每次修改前的自动备份（各保留 20 份） |
| `/opt/vps-relay/` | sing-box 程序和面板代码 |

服务：`sb-relay`（sing-box）和 `vps-relay-panel`（面板）。

## 关于 Gemini 域名

默认列表包含 Gemini、AI Studio、NotebookLM 等相关域名。如果走智能分流节点仍然提示地区不支持，可以在面板里加上 `google.com` 和 `googleapis.com`（让整个 Google 都走 B），或者加 `accounts.google.com` 让登录也走 B。
