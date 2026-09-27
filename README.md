# WG-Chain-Warp (chainproxy)

> **极简、高可用的 Linux 双层 WireGuard 链式代理后端**  
> 一键将你的自建/商业 WireGuard 与 Cloudflare WARP 串联，让 VPS 全局流量经由第一层节点后，最终以 Cloudflare WARP 干净 IP 出海。

---

## ⚡ 极速一键安装

在你的 Linux VPS（支持 Debian 12/13、Ubuntu 22.04/24.04 amd64）上直接运行：

```bash
curl -sSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh | sudo bash
```

> **提示**：脚本会自动安装最新 `sing-box 1.14+` 内核、Rust 守护进程及 systemd 开机自启服务，耗时约 10-30 秒。

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
  1. 查看链路运行状态 (Status & Health)
  2. 配置入口 WireGuard (第一层 VPN / 入口节点)
  3. 配置出口 Cloudflare WARP (手动粘贴 INI)
  4. 一键自动注册 WARP 并生成配置 (Auto Register WARP)
  5. 事务式应用配置并启动 (Apply & Start)
  6. 全链路连通性与分跳测试 (Test & Verify)
  7. 回滚至上一版本配置 (Rollback)
  8. 停止服务并完全恢复网络 (Stop & Cleanup)
  9. 查看系统诊断报告 (Diagnose)
 10. 查看服务运行日志 (Logs)
 11. 重启后台守护服务 (Restart Daemon)
  0. 退出管理菜单
==============================================================
```

### 操作流程：
1. **按 `2`**：直接粘贴你的**入口 WireGuard 配置**（文本支持包含 `[Interface]` 和 `[Peer]`，程序会自动校验格式与公私钥）。
2. **按 `4`**：**一键自动注册 Cloudflare WARP**（程序调用底层 Curve25519 算法生成密钥并向官方申请专属 IP，1 秒自动搞定，无需任何手动抓包）。
3. **按 `5`**：**应用配置并启动**！系统自动下发双层嵌套配置并启动 30 秒看门狗。
4. **按 `6`**：测试出口，回显确认最终出口已变成 Cloudflare WARP IP！

---

## 💡 它是怎么工作的？（通俗易懂）

很多用户希望用自己的小鸡或节点落地，但又想要 Cloudflare 的原生解锁与干净 IP；或者直接连 WARP 会被阻断。

`chainproxy` 将网络自动拼接为如下链条：

```
你的 VPS 宿主机 / 容器应用
       │
       ▼
【第一层：入口 WireGuard 节点】（自建或商业节点，建立底层 UDP 隧道）
       │
       ▼ (隧道内部再加密封装)
【第二层：Cloudflare WARP】（向 Cloudflare Anycast 发起握手）
       │
       ▼
【目标公网网站】（看到的是 Cloudflare 分配给第一层节点所在地区的 WARP 出口 IP）
```

**真正杜绝分流错误**：
- 抓包只能看到 `VPS -> 第一层 WireGuard` 的握手包。
- WARP 流量 100% 走第一层隧道出境，绝无旁路泄漏。

---

## 🛡️ 核心保障与安全设计

- **SSH 绝对不失联**：独家 `conntrack mark 0x88` 连接跟踪技术与应急白名单保护，外部连入 VPS 的 SSH/Web 流量原路返回，即使 VPN 节点异常也不会把自己关在门外。
- **30 秒看门狗自动回滚**：下发配置如果导致网络中断，看门狗将在 30 秒内自动恢复到上一版本网络，无需进 VNC 救援。
- **全面适配 sing-box 1.14+ 现代规范**：使用内核级用户态 `endpoints` 与 `detour` 方案，抛弃已被废弃的旧 outbound 语法，连接延迟更低、吞吐更高。
- **支持 NAT VPS 与端口转发**：兼容各类共享 IPv4 的小鸡与容器，端口转发（DNAT）与小鸡出站互不影响。
- **敏感信息完全脱敏**：私钥在菜单、API、日志中统一显示为 `********`，严禁执行 `PostUp`/`PostDown`，防御代码注入。

---

## 🛠️ 常用快捷命令

除了交互面板外，你也可以随时在终端使用单行命令运维：

```bash
# 打开中文管理菜单（默认）
chainproxy

# 单独触发在线注册 WARP 并打印节点参数
chainproxy warp-reg

# 查看当前链路状态与各分跳健康
chainproxy status

# 触发连通性与分跳延迟测试
chainproxy test

# 回滚到上一版本配置
chainproxy rollback

# 重启后台守护服务
systemctl restart chainproxy

# 查看后台实时日志
journalctl -u chainproxy -f
```

---

## ❓ 常见问题排查 (FAQ)

### Q: 打开菜单提示“无法连接守护进程”或红字错误？
**A**:
1. 请先在菜单中输入 **`11`**（或在终端运行 `sudo systemctl restart chainproxy`）重启后台服务。
2. 运行 `systemctl status chainproxy` 确认服务运行状态。
3. 若您是单独下载的二进制，请使用 `chainproxy daemon` 启动后台。

### Q: 第一层 WireGuard 节点有国家限制吗？
**A**: 没有任何限制。第一层支持任意国家的 WireGuard。Cloudflare WARP 将会通过 Anycast 路由到距离第一层节点最近的边缘数据中心，呈现该地区的 WARP 出口 IP。

---

## 📄 进阶文档

- [系统详细架构与路由设计](docs/architecture.md)
- [安全策略、看门狗与 SSH 保护机制](docs/security_and_rollback.md)
- [REST API 接口规范与参数说明](docs/api.md)
- [完整配置示例 (config.example.json)](examples/config.example.json)

---

## 📜 开源协议

本项目基于 MIT 或 Apache-2.0 协议开源。
