# WG-Chain-Warp (chainproxy)

> **极简、高可用的 Linux 多模式网络代理与链式 WARP 枢纽**  
> 一键将你的自建/商业 WireGuard 或 Socks5 代理与 Cloudflare WARP 串联或独立出站。  
> 支持 **5 种灵活运行模式**：`WG -> WARP`、`Socks5 -> WARP`、`单独 WireGuard`、`单独 Socks5`、`单独 WARP`。

---

## ⚡ 极速一键安装

在你的 Linux VPS（支持 Debian 12/13、Ubuntu 22.04/24.04 amd64）上直接运行：

```bash
curl -sSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh | sudo bash
```

> **提示**：脚本会自动安装最新代理引擎内核、Rust 守护进程及 systemd 开机自启服务，耗时约 10-30 秒。

---

## 🚀 极速上手：只需两步

安装完成后，在终端直接输入：

```bash
chainproxy
```

即可进入**全中文交互控制面板**：

```text
==============================================================
             chainproxy 多模式网络代理管理面板 (v1.0.2)        
==============================================================
 服务状态: 🟢 运行中 (Running)   活跃版本: 20261003_150000
 当前模式: WireGuard -> WARP 链式代理 (默认模式)
 链路拓扑: VPS [UP] -> WireGuard [Running] -> WARP [Running] -> Internet [OK]
--------------------------------------------------------------
 准备状态: ✅ 所需节点全部就绪！请按 [1] 应用配置并启动服务
--------------------------------------------------------------
【常用控制】
  1. 应用配置并启动服务 (Apply & Start)
  2. 全链路连通性与分跳测试 (Test & Verify)
  3. 停止代理服务并恢复网络 (Stop & Cleanup)
  4. 切换代理运行模式 (Switch Mode)

【节点与出口配置】
  5. 配置 WireGuard 节点 (导入或编辑 .conf / INI)
  6. 配置 Socks5 代理节点 (直接输入 IP:端口 或 带账密链接)
  7. 配置 Cloudflare WARP 出口 (一键自动注册 / 手动配置)
  8. 查看当前所有节点配置详情 (View Config)

【运维与诊断】
  9. 查看服务实时日志 (View Logs)
 10. 一键系统与网络诊断 (Diagnose)
 11. 回滚至上一版本配置 (Rollback)
 12. 重启后台守护服务 (Restart Daemon)
  0. 退出管理菜单
==============================================================
```

### 多种场景操作指引：

- **场景 A：WireGuard -> WARP 链式代理（默认模式）**
  1. 按 **`5`** 导入或粘贴 WireGuard 节点配置；
  2. 按 **`7`** 选择 `[1]` 一键自动注册 WARP 出口（或 `[2]` 手动粘贴配置）；
  3. 按 **`1`** 应用配置并启动服务！
  4. 按 **`2`** 执行全链路连通性与分跳测试。

- **场景 B：Socks5 -> WARP 链式中继出海（省流量 / 借冷门地区）**
  1. 按 **`4`** 切换模式为 `[2] Socks5 -> WARP 链式中继代理`（或按 **`6`** 导入 Socks5 并在提示时确认切换）；
  2. 按 **`6`** 粘贴或输入你的 Socks5 代理信息（支持带有账号密码及特殊字符的完整链接）；
  3. 按 **`7`** 选择 `[1]` 一键自动注册 WARP 出口；
  4. 按 **`1`** 应用配置并启动服务！

- **场景 C：单独 WireGuard 直连出站（不带 WARP）**
  1. 按 **`4`** 切换模式为 `[3] 单独 WireGuard 出站 (无 WARP)`；
  2. 按 **`5`** 导入或粘贴 WireGuard 节点配置；
  3. 按 **`1`** 应用配置并启动服务！

- **场景 D：单独 Socks5 直连出站（不带 WARP）**
  1. 按 **`4`** 切换模式为 `[4] 单独 Socks5 出站 (无 WARP)`；
  2. 按 **`6`** 输入 Socks5 代理链接或 IP:端口；
  3. 按 **`1`** 应用配置并启动服务！

- **场景 E：单独 WARP 直连出站（原生 Cloudflare WARP 出口）**
  1. 按 **`4`** 切换模式为 `[5] 单独 WARP 出站 (原生直连)`；
  2. 按 **`7`** 选择 `[1]` 一键自动注册 WARP 出口；
  3. 按 **`1`** 应用配置并启动服务！

---

## ✨ 最新特性与功能解读（通俗易懂）

### 1. 🔀 5 种代理模式随心切换 (按 `4`)
- **WG -> WARP 双层链式**：经典双层混淆，前置 WireGuard 隧道 + WARP 干净出口。
- **Socks5 -> WARP 链式中继**：Socks5 前置中继承载 WARP，获取前置同地区 WARP 干净 IP，出站不走普通代理线路，省流省钱。
- **单独 WireGuard 直连出站**：无需 WARP，VPS 全局流量直接由指定 WireGuard 节点出境。
- **单独 Socks5 直连出站**：无需 WARP，VPS 全局流量直接由指定 Socks5 代理出境。
- **单独 WARP 直连出站**：原生直连 Cloudflare WARP。

### 2. 🔐 智能 Socks5 自动解析与严格隐私脱敏 (按 `6`)
- **智能兼容**：支持 `user:pass@host:port`、`socks5://...`、`host:port:user:pass` 等几乎所有主流厂商与包含任意特殊字符的格式。
- **隐私保护**：密码自动掩码脱敏（`********`），日志与面板均绝不泄露敏感凭证。

### 3. 🌐 Cloudflare WARP 自动开通与配置 (按 `7`)
- **一键极速开通**：内建官方 Cloudflare 注册 API 交互，无需额外安装 Cloudflare 客户端即可秒级生成专有 WARP 账号与密钥。
- **保留地址 (Reserved) 支持**：自动注入与维护 Cloudflare WireGuard 标准 reserved 握手标记，确保握手百分之百成功。

### 4. 🔍 节点配置与详情一览 (按 `8`)
- 随时按 **`8`** 查看当前生效模式、WireGuard 节点（IP、端点、公钥、DNS 等）、Socks5 节点及 WARP 出口配置。
- 支持按 **`1`** 或 **`2`** 查看底层 WireGuard 原始配置文本，排错或核对一目了然。

### 5. 🛠️ 容器环境与 TUN 设备自愈 (/dev/net/tun 自动修复)
- 针对 LXC、Docker、Incus 或最小化精简系统缺少 `/dev/net/tun` 设备节点的常见问题，系统在服务启动、配置应用及安装脚本中均自动执行 `modprobe tun` 并通过 `mknod` 创建设备节点，彻底根治 `open /dev/net/tun: no such file or directory` 异常。

### 6. 🧠 链式拓扑智能判定与分跳探测 (按 `2`)
- WARP 流量物理上必须经过前置节点中继封装。
- 只要 WARP 成功连通并呈现对应地区出口，系统即智能判定底层载体正常，彻底避免因前置节点未开启裸公网 NAT 导致的探测误报。单独模式下亦能智能适配对应的单跳检测。

### 7. 🛡️ SSH 绝对零失联 (conntrack 0x88 保护)
- 无论前置节点配置了什么路由，外部连入 VPS 的 SSH 管理连接与端口转发均受 `conntrack mark 0x88` 策略路由强行原路回程，绝不会失联封门。

### 8. ⏱️ 30 秒看门狗自动回滚 (异常可按 `11` 手动回滚)
- 任何网络变更都有安全看门狗兜底。若链路应用后出现网络断联，看门狗将在 30 秒内全自动回滚到初始网络状态，安全无忧。

### 9. 📜 统一多层运行日志 (按 `9`)
- 一键获取 systemd 守护服务日志与底层代理引擎实时运行日志，任何建连细节与报错均清晰透明。

### 10. 🩺 一键系统与网络诊断 (按 `10`)
- 快速全面体检内核版本、网络接口、TUN 设备、默认网关、DNS 解析、防火墙及 systemd 服务状态。

---

## 💡 它是怎么工作的？

```
你的 VPS 宿主机 / 容器应用
       │
       ▼
【第一层：入口 WireGuard 节点】（建立底层 UDP 隧道，例如摩洛哥节点）
       │
       ▼ (在隧道内部发起 WARP 握手，二次加密)
【第二层：Cloudflare WARP 出口】（向 Cloudflare Anycast 发起握手）
       │
       ▼
【目标公网网站】（看到的是 Cloudflare 分配给第一层节点所在地区的 WARP 出口 IP）
```

**真正杜绝分流错误**：
- 外网抓包只能看到 `VPS -> 第一层 WireGuard` 的通信流量；
- WARP 流量 100% 经由第一层节点中转出境，无旁路泄漏。

---

## 🛠️ 常用命令行快捷操作

除了控制面板，也可直接在终端单行执行运维命令：

```bash
# 打开中文交互管理菜单（默认）
chainproxy

# 快速触发注册一次 WARP 并打印节点配置
chainproxy warp-reg

# 查看当前链路状态与各分跳拓扑
chainproxy status

# 触发全链路连通性与分跳延迟测试
chainproxy test

# 回滚到上一版本配置并恢复网络
chainproxy rollback

# 完全停止代理并清理全部防火墙规则
chainproxy stop

# 重启后台守护服务
systemctl restart chainproxy

# 查看后台实时日志
journalctl -u chainproxy -f
```

---

## ❓ 常见问题排查 (FAQ)

### Q: 第一层 WireGuard 节点必须是哪些地区的？
**A**: **支持全球任意国家和地区的 WireGuard 节点**。Cloudflare WARP 会根据第一层节点的出口公网 IP，自动分配该地区最近的 Cloudflare 数据中心及当地 WARP IP（例如第一层是摩洛哥，最终出口就是摩洛哥 WARP IP）。

### Q: 第一层显示未通过但 WARP 畅通能上网，正常吗？
**A**: **完全正常**。因为 WARP 是由第一层节点承载的，WARP 能通就 100% 证明第一层隧道正在工作。部分第一层节点本身是中继网关，不支持未经 WARP 封装的纯 HTTP/HTTPS 直连。

### Q: 如何彻底卸载并恢复服务器网络？
**A**: 在菜单中选择 **`3. 停止代理服务并恢复网络`**（或执行 `chainproxy stop`），防火墙规则和路由表会自动全部清理撤销，恢复 VPS 原生网络。

### Q: 启动提示 `open /dev/net/tun: no such file or directory` 怎么解决？
**A**: v1.0.2 版本已内建 `/dev/net/tun` 自动创建与修复机制。如果您运行在 LXC/Incus 等无特权容器内且宿主机未允许 TUN，需在宿主机容器配置文件中添加允许设备直通（如 `lxc.cgroup2.devices.allow = c 10:200 rwm`）。

---

## 📄 进阶文档

- [系统详细架构与路由设计](docs/architecture.md)
- [安全策略、看门狗与 SSH 保护机制](docs/security_and_rollback.md)
- [REST API 接口规范与参数说明](docs/api.md)
- [完整配置示例 (config.example.json)](examples/config.example.json)

---

## 📜 开源协议

本项目基于 MIT 或 Apache-2.0 协议开源。
