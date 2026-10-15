# WG-Chain-Warp (chainproxy)

> **极简、高性能的 Linux 链式 WireGuard + WARP 代理枢纽（内置 x-ui 风格 Web 控制台）**  
> 一键将自建/商业 WireGuard 或 SOCKS5 代理与 Cloudflare WARP 串联或独立出站，全可视化 Web 面板管理。  
> 支持 **6 种运行模式**：`WG -> WARP`、`Socks5 -> WARP`、`单独 WireGuard`、`单独 Socks5`、`单独 WARP`、`SOCKS5 服务端（本机直连）`。

---

## ⚡ 极速一键安装

在你的 Linux VPS / 云服务器（支持 Debian 12/13、Ubuntu 22.04/24.04 amd64）上直接运行：

```bash
curl -fsSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh | sudo bash
```

支持在安装时通过环境变量一步自定义 Web 面板端口与账号密码（可选）：

```bash
curl -fsSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh | sudo PANEL_PORT=54321 PANEL_USER=admin PANEL_PASS=admin bash
```

> **提示**：脚本全自动静默完成依赖检查、`sing-box` 内核安装、`chainproxy` 部署及 `systemd` 守护服务启动，全程无需人工干预。

---

## 🖥️ Web 控制台极速上手

安装完成后，终端会直接输出你的 **Web 控制台访问地址**：

- **访问地址**：`http://<服务器IP>:54321/`
- **默认账号**：`admin`
- **默认密码**：`admin`

### Web 面板四大核心模块：

1. **系统状态 (Dashboard)**
   - 实时监控 CPU、内存、Swap、磁盘占用、实时网速与累计流量（基于内核 `/proc` 零进程开销采集）。
   - 一键切换 **6 种运行模式**，可视化展示 **第一跳（前置 WG/SOCKS5）** 与 **第二跳（WARP/最终出口）** 的连通状态、延迟与出口 IP / 运营商信息。
   - 顶部支持一键 **应用并启动**、**连通性测试**、**回滚配置** 与 **停止代理**。

2. **链式与节点配置**
   - **前置 WireGuard 节点**：支持直接粘贴完整 `.conf` 配置文件一键解析填入，或表单编辑密钥、Endpoint 与 MTU。
   - **前置 SOCKS5 节点**：支持粘贴 `socks5://user:pass@host:port`、`host:port:user:pass` 等格式一键解析，密码自动脱敏保护。
   - **Cloudflare WARP 出口**：支持面板内 **一键自动注册全新 WARP 账号**（自动获取密钥与 `reserved` 字段），或粘贴已有配置。

3. **SOCKS5 服务端**
   - 将本机作为多用户认证的 SOCKS5 服务端（直连出站，不创建 TUN、不改路由表）。
   - 支持可视化配置监听地址端口（如 `0.0.0.0:1080`）及在线增删改账号密码。

4. **面板设置与日志诊断**
   - 在线修改 Web 面板监听地址、端口、根路径（Base Path）、登录用户名与密码，以及切换深色/浅色主题。
   - 在线切换 `sing-box` 日志级别（`debug` / `info` / `warn` / `error`）、查看实时运行日志及一键运行网络环境诊断。

---

## 🛠️ 终端管理菜单与 CLI 命令

参照 `x-ui` 设计，终端 `chainproxy` 专注于 **服务生命周期管理与面板参数维护**（所有节点配置均在 Web 面板完成）：

在终端输入 `chainproxy` 即可打开管理菜单：

```text
==========================================================
         chainproxy 服务与 Web 面板管理脚本
==========================================================
  Web 面板状态: 运行中 (Active)
  Web 面板地址: http://<IP>:54321/ (账号: admin)
----------------------------------------------------------
  0. 退出脚本
——————————————————————————————————————————————————————————
  1. 启动后台守护与 Web 面板
  2. 停止服务并清理代理规则
  3. 重启后台守护与 Web 面板
  4. 查看服务状态与当前模式
——————————————————————————————————————————————————————————
  5. 修改 Web 面板用户名与密码
  6. 修改 Web 面板监听端口
  7. 修改 Web 面板根路径 (Base Path)
  8. 查看当前 Web 面板配置信息
  9. 重置 Web 面板账号密码为 admin
——————————————————————————————————————————————————————————
  10. 查看实时运行日志 (journalctl)
  11. 触发全链路连通性测试
  12. 紧急回滚上一版本并恢复网络
```

### 常用命令行快捷指令：

```bash
# 打开交互式服务与面板管理菜单
chainproxy

# 命令行直接查看或修改 Web 面板配置
chainproxy setting --show
chainproxy setting --port 54321 --username admin --password 新密码

# 重置 Web 面板账号密码为默认 admin / admin
chainproxy setting --reset

# 查看当前运行状态与出口信息
chainproxy status

# 触发全链路连通性与分跳延迟测试
chainproxy test

# 紧急回滚到上一版本配置并恢复宿主机网络
chainproxy rollback

# 停止代理并清理全部策略路由与 nftables 规则
chainproxy stop
```

---

## ✨ 核心架构与性能优势

1. **高性能 Mixed TUN 栈**：采用 `system` TCP 栈 + `gvisor` UDP 栈组合，大幅降低高吞吐场景下的 CPU 占用与延迟。
2. **零子进程轮询开销**：仪表盘通过 `/proc` 直接读取系统指标并缓存路由快照，消除高频子进程调用与磁盘 I/O。
3. **并发双跳健康探测**：第一跳与第二跳连通性探测并发执行，测试耗时减半，出口 IP 与 ISP 状态持久展示。
4. **入站连接物理回程保护 (`conntrack 0x88`)**：自动对入站 SSH 及 Web 面板连接打标，走物理网卡主路由表回包，确保开启全局代理后 SSH 与 Web 面板永不失联。
5. **30 秒硬件级看门狗自动回滚**：配置变更应用过程中若出现异常，看门狗自动回滚并清理策略路由与防火墙规则。

---

## 📜 开源协议

本项目基于 MIT 或 Apache-2.0 协议开源。
