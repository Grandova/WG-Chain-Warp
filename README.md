# WG-Chain-Warp (chainproxy)

> **极简、高可用的 Linux 双层 WireGuard 链式代理后端**  
> 一键将你的自建/商业 WireGuard 与 Cloudflare WARP 串联，让 VPS 全局流量经由第一层节点后，最终以 Cloudflare WARP 干净 IP 出海。

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
             chainproxy 链式 WireGuard 代理管理面板            
==============================================================
 服务状态: Running      活跃版本: 20260927_183049
 链路拓扑: VPS [UP] -> VPN1 [Running] -> WARP [Running] -> Internet [OK]
--------------------------------------------------------------
  1. 查看链路运行状态 (Status & Health)
  2. 配置入口 WireGuard (第一层 VPN / 入口节点)
  3. 配置出口 Cloudflare WARP (手动粘贴 INI)
  4. 一键自动注册 WARP 并生成配置 (Auto Register WARP)
  5. 事务式应用配置并启动 (Apply & Start)
  6. 全链路连通性与分跳测试 (Test & Verify)
  7. 查看节点配置详情 (View Node Configs)
  8. 回滚至上一版本配置 (Rollback)
  9. 停止服务并完全恢复网络 (Stop & Cleanup)
 10. 查看系统诊断报告 (Diagnose)
 11. 查看服务运行日志 (Logs)
 12. 重启后台守护服务 (Restart Daemon)
  0. 退出管理菜单
==============================================================
```

### 标准操作三部曲：
1. **按 `2`**：粘贴你的**入口 WireGuard 配置**（直接粘贴包含 `[Interface]` 和 `[Peer]` 的配置文本，系统自动解析并校验公私钥）。
2. **按 `4`**：**一键自动注册 Cloudflare WARP**（内置官方 API 对接，1 秒全自动获取并绑定出口配置，免抓包）。
3. **按 `5`**：**应用配置并启动**！系统自动完成双层嵌套隧道组网、策略路由下发与连通性验证。
4. **按 `6`**：随时执行测试，确认公网出口已变更为目标国家的 Cloudflare WARP IP！

---

## ✨ 最新特性与功能解读（通俗易懂）

### 1. 🔍 节点配置一览 (按 `7`)
- 随时按 **`7`** 查看当前生效的入口节点（IP、端点、公钥、DNS 等）与 WARP 出口配置。
- 进一步支持按 **`1`** 或 **`2`** 查看原始 INI 文本，排错或核对一目了然。

### 2. ⚡ 缺失环境就地自愈
- 当你在全新机器上运行面板按 **`5`** 启动时，如果系统未安装底层引擎，面板会**就地全自动拉取安装**并继续启动，无需退出重来。

### 3. 🧠 链式拓扑智能判定
- WARP 流量物理上必须经过第一层入口节点进行 UDP 隧道封装。
- 只要 WARP 成功连通并呈现对应地区出口，系统即智能判定底层载体隧道正常，彻底避免因第一层节点未开启裸公网 NAT 导致的直连探测误报。

### 4. 🛡️ SSH 绝对零失联 (conntrack 0x88 保护)
- 无论第一层 VPN 配置了什么路由，外部连入 VPS 的 SSH 管理连接与端口转发均受 `conntrack mark 0x88` 策略路由强行原路回程，绝不会失联封门。

### 5. ⏱️ 30 秒看门狗自动回滚
- 任何网络变更都有安全看门狗兜底。若链路应用后出现网络断联，看门狗将在 30 秒内全自动回滚到初始网络状态，安全无忧。

### 6. 📜 统一多层运行日志 (按 `11`)
- 一键获取 systemd 守护服务日志与底层 sing-box 引擎运行日志，任何建连细节与报错均清晰透明。

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
**A**: 在菜单中选择 **`9. 停止服务并完全恢复网络`**（或执行 `chainproxy stop`），防火墙规则和路由表会自动全部清理撤销，恢复 VPS 原生网络。

---

## 📄 进阶文档

- [系统详细架构与路由设计](docs/architecture.md)
- [安全策略、看门狗与 SSH 保护机制](docs/security_and_rollback.md)
- [REST API 接口规范与参数说明](docs/api.md)
- [完整配置示例 (config.example.json)](examples/config.example.json)

---

## 📜 开源协议

本项目基于 MIT 或 Apache-2.0 协议开源。
