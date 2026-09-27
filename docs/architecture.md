# chainproxy 架构与网络核心设计

## 1. 架构目标与拓扑

本项目实现多层 WireGuard 链式转发服务，核心拓扑如下：

```
[宿主机应用 / NAT VPS 小鸡容器]
               │
               ▼ (tun: chain0 172.31.255.1/30)
         [sing-box 1.14+]
               │
               ▼ (detour)
    [WARP WireGuard Outbound]
  (内层 WireGuard 隧道, 端点 162.159.192.1:2408)
               │
               ▼ (detour)
   [VPN1 WireGuard Outbound]
  (外层 WireGuard 隧道, 端点 198.51.100.1:51820)
               │
               ▼ (bind_interface: "eth0" + routing_mark)
      [physical-direct Outbound]
               │
               ▼
       [物理网卡 eth0]
               │
               ▼ (UDP 封包)
       [VPN1 Server]
               │ (解开外层)
               ▼
     [Cloudflare WARP Server]
               │ (解开内层)
               ▼
          [Internet]
```

物理网卡抓包特征：
- 物理网卡 `eth0` 上只存在：`Host -> VPN1 Endpoint` 的外层 UDP 流量。
- 绝不会直接看到 `Host -> WARP Endpoint` 或 `Host -> Internet` 的明文旁路连接。
- 最终公网出口 IP 严格呈现为 Cloudflare WARP IP。

---

## 2. 路由环路防范机制

在内核 WireGuard（`wireguard-linux`）中，内核驱动给封装 UDP 数据包标记 `sk->sk_mark = wg->fwmark`，通过策略路由 `ip rule add not fwmark <mark> table <tun_table>` 避免循环入网。

而在 `chainproxy` 中，我们结合了**用户态嵌套**与**双重策略路由保护**：
1. **用户态内存直接移交**：WARP 端点的数据包在 sing-box 进程内直接 detour 给 VPN1，根本不进内核网络协议栈，物理上消除中间路由劫持。
2. **底层直连绑定 (`bind_interface`)**：`physical-direct` 显式设置 `bind_interface: "eth0"`，并通过 `SO_BINDTODEVICE` 限制出口。
3. **VPN1 Endpoint 主机明细路由保护**：配置生效时在 `main` 路由表中插入指向 VPN1 端点的主机明细路由（`ip route add <vpn1_ip> via <gw> dev eth0 table main`），确保其握手包无论如何不走 TUN。

---

## 3. conntrack mark 入站回程保护

对于公网入站的 SSH、HTTP、HTTPS、面板等服务，必须确保回程原路返回：

### Netfilter 钩子时序表
| 阶段 | 优先级 | 操作 | 目的 |
|---|---|---|---|
| PREROUTING | mangle (-150) | `iifname "eth0" ct state new ct mark set 0x88` | 记录“外部从物理网卡进来的新连接” |
| PREROUTING | mangle (-150) | `ct mark 0x88 meta mark set 0x88` | 连接反向数据包继承 fwmark |
| PREROUTING | dstnat (-100) | 用户已有 DNAT 规则执行 | 完全兼容 NAT VPS 端口转发 |
| OUTPUT | mangle (-150) | `ct mark 0x88 meta mark set 0x88` | 本机服务回复包打上 fwmark 并触发重路由 |
| ROUTING | priority 90 | `ip rule add fwmark 0x88 lookup main` | 命中 main 表，从 eth0 发回客户端 |

---

## 4. NAT VPS 端口转发与容器出站

- **场景 A：外部访问小鸡 (DNAT)**
  外部客户端通过 `eth0:10022` 访问 NAT 小鸡 `10.0.0.2:22`。
  入站时打标 `0x88`，小鸡回程包在宿主机识别为反向流，自动匹配 `fwmark 0x88` 经由 `eth0` 响应客户端，端口转发丝毫不受影响。
- **场景 B：小鸡主动访问公网**
  小鸡主动向公网发起连接，流量来自内部网桥（如 `incusbr0`），不满足 `iifname eth0`，因此 `ct mark` 为 0。
  流量进入 sing-box TUN，经由 `WARP -> VPN1 -> Internet`，出口为 WARP IP。
