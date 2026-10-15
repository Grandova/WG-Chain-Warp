# Sooya (`v1.6.0`)

> **极致轻量、纯 Rust 原生内核的 Linux 链式 WireGuard + WARP + SOCKS5 出站代理面板**  
> 一键将自建/商业 WireGuard 或 SOCKS5 节点与 Cloudflare WARP 串联或独立出站；支持**本机 SOCKS5 服务端与任意 WireGuard/WARP 出站节点同时开启**，让其他设备连接本机 SOCKS5 即可直接共享当前 WireGuard/WARP 出站线路！  
> **仅接管本机主动出站流量 (`0x800`) 与隧道内 DNS，入站连接 (`0x88`，SSH / Web / 业务端口) 100% 原路物理网卡返回，绝不失联。**

---

## ⚡ 一键安装与升级

在你的 Linux 服务器（Debian 11/12/13、Ubuntu 20.04/22.04/24.04、CentOS 7+ `x86_64 / amd64`）上直接运行以下任意一条命令：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/install.sh)
```

或使用 `scripts/install.sh` 路径（两者完全等效）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh)
```

如果已安装过 `sooya`，也可以直接在终端执行：

```bash
sooya update
```

支持通过环境变量在安装时直接指定面板端口与账号密码（可选）：

```bash
curl -fsSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/install.sh | sudo PANEL_PORT=54321 PANEL_USER=admin PANEL_PASS=admin bash
```

> **极致轻量**：安装脚本直接拉取 GitHub Releases 预编译静态二进制包 `sooya-linux-amd64.tar.gz`，**不在目标机器上拉取源码或执行本地编译**，运行时内存占用仅 **~2.5 MB**，空闲 CPU **0.0%**。

---

## 🖥️ Sooya Web 控制台

安装完成后，终端会自动输出面板访问信息：

- **访问地址**：`http://<服务器IP>:54321/`（若之前自定义过端口如 `5000`，会自动保留原端口）
- **默认用户名**：`admin`
- **默认密码**：`admin`

### 核心亮点与功能

1. **毫秒级节点启停与丝滑交互体验**
   - **秒开零等待**：启用 WireGuard 或 WARP 出站节点时，内核完成 TUN 网卡与批处理策略路由挂载后**立即返回（< 150ms）**，出口 IP 与地理位置归属在后台异步探测并自动回填，告别漫长的“正在握手”阻塞等待。
   - **乐观 UI 即时响应 (`0ms`)**：点击顶部全局模式切换按钮或节点列表开关时，界面开关与模式高亮 `0ms` 即时响应，切换节点模式无需重新销毁表格 DOM，杜绝任何闪烁与卡顿。
   - **单请求极速首屏 (`/panel/api/bootstrap`)**：首帧 `0ms` 本地缓存水合，单次请求聚合加载全部状态，支持深色/浅色主题一键切换。

2. **全局模式一键切换 & 5 大出站模式 + 并行 SOCKS5 服务端**
   - **`🛡️ 仅 WireGuard 出站` (`standalone_wg`)**：本机主动出站流量与全量 DNS 直接走您配置的 WireGuard 节点出站（解决就近 CDN 解析，杜绝 DNS 泄露与回环绕路）。
   - **`🔗 WG + WARP 链式出站` (`wg_chain_warp`)**：`VPS -> 前置 WireGuard -> Cloudflare WARP -> 目标公网`，在出站列表中可直接下拉一键切换「仅 WG 直出」或「WG + WARP 链式」并立即生效。
   - **`☁️ 仅 WARP 免配置出站` (`standalone_warp`)**：零配置自动向 Cloudflare 注册免费 WARP 密钥并优选低延迟 Anycast 端点。
   - **`🧦 SOCKS5 + WARP 链式出站` (`socks_chain_warp`)**：`VPS -> 前置 SOCKS5 -> Cloudflare WARP -> 目标公网`。
   - **`🔌 本机 SOCKS5 服务端` (`socks5_server`，支持与任意出站模式同时开启！)**：
     - 独立守护运行，开关耗时 **< 2ms**，绝不打断正在运行的 WireGuard / WARP 隧道。
     - **共享出站能力**：当与 `WireGuard` 或 `WARP` 同时开启时，外部设备连接本机 SOCKS5 服务端（支持 TCP `CONNECT` 与 UDP `UDP ASSOCIATE`）的流量与域名解析将**自动走当前启用的 WireGuard / WARP 节点出站**，且回包强制打标 `0x400` 走物理网卡直回客户端，绝不回环！

3. **运行日志与策略路由诊断**
   - 在线查看 `journalctl -u sooya` 实时日志。
   - 一键检查 Linux 策略路由表 (`ip rule` / `table 2023`) 与 `nftables` 防火墙规则。

---

## 🛠️ Sooya 终端管理命令

在终端直接输入 `sooya` 即可呼出交互式管理菜单，或使用快捷子命令：

```bash
sooya              # 显示交互式管理菜单
sooya start        # 启动 Sooya 面板
sooya stop         # 停止代理并安全恢复宿主机原网络
sooya restart      # 重启 Sooya 面板
sooya status       # 查看 Sooya 实时链路状态
sooya enable       # 设置 Sooya 开机自启
sooya disable      # 取消 Sooya 开机自启
sooya log          # 查看 Sooya 运行日志
sooya update       # 在线更新 Sooya 至最新版本
sooya uninstall    # 卸载 Sooya 面板
sooya setting --port 54321 --username admin --password 新密码
```

---

## ✨ 底层架构与安全保证

- **自研纯 Rust 用户态 WireGuard & WARP 内核 (`Sooya WarpKernel`)**：
  - 彻底摒弃官方 `cloudflare-warp` (`warp-svc`，150MB+ 内存) 与外部 Go/C 进程，单二进制零外部运行时依赖。
  - 原生实现 Noise_IK 握手、X25519、ChaCha20-Poly1305、BLAKE2s、Cloudflare 3 字节 `reserved` (`client_id`) 注入，以及 `2408 / 500 / 4500 / 1701` 多端口 Anycast 自动优选。
- **严格出入站隔离（100% 不影响入站流量）**：
  - 入站连接在 `prerouting` 自动记录 `ct mark 0x88`，回包强制走主路由表从原物理网卡返回，SSH、Web 面板及本机所有对外服务端口 100% 不受影响。
  - 仅本机发起的主动出站连接（`ct state new`）打标 `0x800` 路由至 `table 2023` (`chain0`)，并自动接管全量 UDP/TCP 53 DNS 请求通过隧道远端解析。
- **毫秒级批处理路由切换与事务自愈回滚**：
  - 采用 `ip -force -batch -` 单次批处理安装/清理规则，启停切换丝滑顺畅；任何异常自动回滚恢复原网络。

---

## 📜 开源协议

MIT OR Apache-2.0
