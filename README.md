# Sooya

> **轻量化、高性能的 Linux 链式 WireGuard + WARP 代理面板（x-ui 风格 Web 控制台）**  
> 一键将自建/商业 WireGuard 或 SOCKS5 节点与 Cloudflare WARP 串联或独立出站，预编译静态二进制秒级安装，无需在机器上编译源码。  
> 支持 **6 种运行模式**：`WG -> WARP`、`Socks5 -> WARP`、`单独 WireGuard`、`单独 Socks5`、`单独 WARP`、`SOCKS5 服务端（本机直连）`。

---

## ⚡ 一键安装与升级

在你的 Linux 服务器（Debian 12/13、Ubuntu 22.04/24.04、CentOS 7+ `amd64`）上直接运行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh)
```

或使用 `curl | sudo bash` 静默安装：

```bash
curl -fsSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh | sudo bash
```

支持通过环境变量在安装时直接指定面板端口与账号密码（可选）：

```bash
curl -fsSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh | sudo PANEL_PORT=54321 PANEL_USER=admin PANEL_PASS=admin bash
```

> **轻量化设计**：安装脚本直接拉取 GitHub Releases 预编译压缩包 `sooya-linux-amd64.tar.gz`（~2.8 MB）解压至 `/usr/local/sooya/`，**绝不在目标机器上拉取源码或执行本地编译**，零额外内存/CPU 负担。

---

## 🖥️ Sooya Web 控制台

安装完成后，终端会自动输出面板访问信息：

- **访问地址**：`http://<服务器IP>:54321/`
- **默认用户名**：`admin`
- **默认密码**：`admin`

### 面板核心功能：

1. **系统状态监控 (Dashboard)**
   - 实时仪表盘监控 CPU、内存、Swap、硬盘使用率、TCP/UDP 连接数、实时上下行速率与累计流量。
   - 可视化展示 **第一跳（入口 WG / SOCKS5）** 与 **第二跳（Cloudflare WARP / 最终出口）** 的连通状态、延迟与公网出口 IP / 归属地 / 运营商。
   - 一键执行 **启动/重载**、**停止代理**、**分跳连通性探测**。

2. **链式与节点配置**
   - **6 种工作模式一键卡片切换**：自动按所选模式精简下方表单配置项。
   - **入口 WireGuard 节点**：支持导入 `.conf` 文件或直接粘贴标准配置。
   - **入口 SOCKS5 节点**：支持粘贴 `user:pass@host:port`、`socks5://...`、`host:port:user:pass` 一键智能解析。
   - **Cloudflare WARP 出口**：内置官方接口，点击 **「⚡ 一键自动注册生成 WARP」** 即可自动生成密钥与配置。
   - **本机 SOCKS5 服务端**：支持多账号认证管理与一键复制 `socks5://` 分享链接。

3. **运行日志与系统诊断**
   - 在线切换 `sing-box` 日志级别（`info` / `debug` / `warn` / `none`）。
   - 在线查看实时运行日志与一键生成系统策略路由 / `nftables` 诊断报告。

4. **面板设置**
   - 在线修改面板监听 IP、监听端口、URL 根路径（Base Path）以及登录用户名与密码。

---

## 🛠️ Sooya 终端管理脚本使用方法

在终端直接输入 `sooya` 即可呼出 `x-ui` 风格管理菜单：

```text
  Sooya 面板管理脚本 v1.4.0
  Web 面板地址: http://<IP>:54321/
  面板状态: 运行中  |  sing-box 引擎: 运行中
  0. 退出脚本
————————————————
  1. 更新 Sooya
  2. 卸载 Sooya
————————————————
  3. 重置用户名密码
  4. 重置面板设置
  5. 设置面板端口与根路径
  6. 查看当前面板设置
————————————————
  7. 启动 Sooya
  8. 停止 Sooya
  9. 重启 Sooya
 10. 查看 Sooya 状态
 11. 查看 Sooya 日志
————————————————
 12. 设置 Sooya 开机自启
 13. 取消 Sooya 开机自启
```

### 常用命令行快捷指令：

```bash
sooya              # 显示管理菜单 (功能更多)
sooya start        # 启动 Sooya 面板
sooya stop         # 停止 Sooya 面板与代理并恢复网络
sooya restart      # 重启 Sooya 面板
sooya status       # 查看 Sooya 状态
sooya enable       # 设置 Sooya 开机自启
sooya disable      # 取消 Sooya 开机自启
sooya log          # 查看 Sooya 运行日志
sooya update       # 在线更新 Sooya 面板
sooya uninstall    # 卸载 Sooya 面板
sooya setting --port 54321 --username admin --password 新密码
```

---

## ✨ 性能与安全特性

- **Mixed 高性能 TUN 栈**：采用内核级 `system` TCP + `gvisor` UDP 组合栈，兼顾高吞吐低 CPU 占用与 UDP 转发兼容性。
- **零子进程轮询开销**：系统监控直接读取 Linux `/proc` 虚拟文件系统并缓存路由状态，极低资源占用。
- **SSH 与面板零失联保护 (`conntrack 0x88`)**：入站管理连接自动打标并强制走物理网卡主路由表回程，开启全局代理后 SSH 与 Web 面板永不断联。
- **30 秒事务看门狗回滚**：应用配置异常时自动回滚至上一可用版本并清理防火墙/策略路由规则。

---

## 📜 开源协议

MIT OR Apache-2.0
