# Linux 路由隔离

本次范围是 routing / forwarding / gateway isolation，保留原来的五种 sing-box 出口、配置字段、REST 路由和 CLI。协议数据由 sing-box、Linux WireGuard、Dante 实现，项目不实现新的 WireGuard/SOCKS wire format。

## 审计与架构对照

| 项目 | 原实现 | 当前实现 |
|---|---|---|
| Host 出站 | auto_route 按 Host 开关启用，接管 table 2022 | OUTPUT 标记 0x800，仅 iif lo 查 table 2023 |
| LAN 出站 | iif/from 手工规则查同一个 table 2022，gateway.enabled 可绕过 forwarding 开关 | PREROUTING 根据真实接口及源网段标记 0x1000，独立查 table 2022 |
| 物理 underlay | 0x400 加一次性 endpoint 地址路由 | 0x400/0x400 查 main；不写 endpoint 主机路由 |
| 入站回程 | ct mark 0x88，filter OUTPUT 改 packet mark | 区分 conntrack original/reply，route OUTPUT 改 mark 触发重新路由 |
| 防火墙 | nftables 加 iptables FORWARD | 只操作 inet chainproxy，含 MSS clamp、forward、mark |
| LAN 网段 | IPv4 最后一段清零并假定 /24 | 读取接口 prefix，main 最长匹配选 LAN 接口 |
| 生命周期 | 按 priority 删除、部分命令忽略错误、并行 watchdog 清理 | 完整规则选择器加 protocol 186，持久化快照，串行失败恢复 |
| 健康检查 | 代理失败后可能以主机直连成功代替 | 必须对应代理测试端口成功；物理直连不代表代理健康 |

旧 packet flow：

~~~text
Host -> sing-box auto_route -> table 2022 -> chain0
LAN  -> 手工 iif/from rule -> table 2022 -> chain0
回程 -> filter OUTPUT 设置 mark（不能据此保证重查路由）
WG/SOCKS endpoint -> 0x400 / 固定地址旁路 -> main
~~~

新 packet flow：

~~~text
外部 -> 本机服务 -> ct reply -> route OUTPUT mark 0x88 -> main
Host -> route OUTPUT -> 0x800 -> table 2023 -> chain0
LAN  -> PREROUTING iif+source -> 0x1000 -> table 2022 -> chain0
                         局域网/排除地址/已有 main 具体路由 -> main
chain0 -> 所选 WG / WARP / SOCKS detour -> physical-direct 0x400 -> main
Host 开关关闭 -> main；LAN 开关关闭 -> 原有普通转发策略
~~~

main 的 IPv4/IPv6 默认路由从不由本程序增删或替换。sing-box 创建 TUN 地址所需的 connected/local 路由仍由内核与 sing-box 管理。auto_route=false；sing-tun 某些版本仍会创建绑定 TUN 的辅助 IPv6 oif 规则，它们不负责 Host/LAN 选择，随 sing-box 正常退出清理。

## Policy rule 与 mark

旧优先级：70 physical、80 SSH、90 inbound；LAN bypass 为 8989-index，LAN forwarding 为 8990+index；sing-tun auto_route 从 9000 开始（IPv4/IPv6、版本、严格路由选项会影响实际规则，包括 not iif lo 等）。这些规则隐式共享 2022，并可能相互重叠。

新规则如下，IPv4/IPv6 分别安装适用项：

| priority | 匹配 | 动作 |
|---|---|---|
| 0 | 系统 local | 不修改 |
| 70 | mark 0x400/0x400 | lookup main |
| 80 | 当前 SSH_CLIENT/SSH_CONNECTION 中的地址 | lookup main |
| 90 | 入站返回标记（默认 0x88/0x88） | lookup main |
| 100 | Host/LAN 代理标记 + LAN、排除、保留私网等目标 | lookup main |
| 101 | Host/LAN 代理标记 | lookup main suppress_prefixlength 0 |
| 110 | mark 0x1000/0x1c88 | lookup 2022 |
| 111 | 同上 | unreachable，TUN 消失时防止代理流量泄漏 |
| 120 | iif lo + mark 0x800/0x1c88 | lookup 2023 |
| 121 | 同上 | unreachable |
| 32766/32767 | 系统 main/default | 不修改 |

2022 仅承载 LAN，2023 仅承载 Host，启用相应代理时安装 default dev chain0 proto 186。LAN/main 具体路由在 100/101 优先处理，因此不向两张表重复复制 LAN 路由。既有私网直连行为保留。

0x400 是 physical socket mark；0x800/0x1000 仅用于 packet 选择；0x88 保存在入站连接 ct mark，reply 才恢复到 packet mark。保留位掩码默认 0x1c88，修改时保留其余位。自定义 inbound mark 必须非零且不与另外三类重叠；掩码随其扩展。停止时 conntrack -U 仅清除入站保留位，不删除连接或其他位。其他程序不能同时使用这些保留位。

proxy_host_outbound 和 proxy_forwarded_outbound 是最终代理开关。gateway.enabled、auto_allow_lan 用于发现/组合允许网段，不能将显式 false 的 forwarding 开关变为 true。CLI 开关网关会同步调整 forwarding，保持 Host 开关不变。

physical-direct 始终 bind uplink 并设置 0x400；DNS bootstrap 也使用它。Linux 从 resolv.conf 或 systemd-resolved 的真实上游文件选择非 loopback DNS，找不到则明确拒绝启动。链式第二跳保持 detour 到第一跳；不通过固定 endpoint IP 绕过整个链。endpoint 域名由 sing-box 解析，配置 reload 会重新解析；测试覆盖 A 地址改变，不承诺 sing-box 在不中断会话时自动追踪所有 TTL 变化。

## 事务与停止恢复

1. 验证配置、LAN 路由、sing-box 配置，保留旧运行配置。
2. 停止旧实例并恢复基线；拒绝占用的 chain0、保留优先级以及任何引用/占用 2022/2023 的外部资源。
3. 保存原 ip rules、专用表路由、仅本项目 nft 表、sysctl 到持久化 network_snapshot.json，再开始修改。
4. 配置 sysctl，安装旁路/选择规则，启动 sing-box，确认 TUN 出现，再安装表默认路由；最后启用 nft 标记。
5. 实际代理健康检查成功后持久化 last_known_good、提交版本。失败或 watchdog 到期走同一个恢复路径；reload 失败尝试重新启动此前已提交配置。

停止顺序为关闭 nft 流量选择、SIGTERM 等待 sing-box 清理、按完整选择器删除本次规则/路由、恢复原 nft 表和 sysctl、清除本项目 conntrack 位。失败保留 journal 供再次 stop 重试；重复 stop 可安全执行。不 flush main、全系统 nftables、iptables 或 conntrack。

IPv4 ip_forward 切换会间接重置接口参数，因此快照包含原 IPv4 conf 参数；IPv6 保存 forwarding/accept_ra 并保留 RA 接收能力。不会全局禁用 IPv6，也不写持久 sysctl 文件。

Linux 子进程设置 parent-death SIGTERM；daemon 被 SIGKILL 后 sing-box 退出，入站物理回程仍可用。新的 engine 在 stop/apply 时恢复磁盘 journal。SIGKILL 无法执行 Rust 清理，因此代理标记规则会保留至新实例恢复；选中的代理出站此时 fail closed，不将它报告为“已自动全部恢复”。

## 升级与防火墙边界

- 先通过旧版本正常停止，再替换二进制并启动。旧版没有 journal 的残留规则无法可靠判断归属，新版会拒绝冲突，不按 priority 盲删。用 diagnose 检查 2022/2023、8989/8990 及 sing-tun 9000 段，确认归属后由原管理者清理。
- 安装依赖新增 conntrack；脚本只使用 nftables。Docker/Incus/PVE 或用户防火墙的独立 drop 仍然有效，一个 nft base chain 中的 accept 不能覆盖其他 base chain 的 drop，需要网络管理员已有转发策略允许。
- 回程遵循 main 的物理路由。此设计对应单物理默认出口；多 WAN 对称回程需要系统本身正确的 main/source 策略，本次未新增按入口维护多 WAN 路由表。
- routing.ipv6=false 表示不选择 IPv6 代理，保留系统原有 IPv6 路由，并非全局封禁 IPv6。
- main 中更具体的静态路由会优先于代理默认路由，保留现有本地网络和管理路由语义。

## 真实 Linux 测试

测试文件为 examples/netns_driver.rs、tests/network_namespace.py、tests/tls_relay.py。driver 直接调用生产 Rust 实现。三个独立 network namespace 通过 veth 连接，所有路由、防火墙、sysctl 修改均在其中；结束前后比较真实宿主机网络。使用 nsenter 进入网络 namespace，避免 ip netns exec 在受限容器内额外挂载 /sys。

独立实现：Linux kernel WireGuard 作为 WG/WARP 协议对端，Dante 1.4.2 作为 SOCKS5 TCP/UDP 对端，curl/dig/dnsmasq 发起或处理真实网络数据。WARP 模式验证的是相应生成配置与 WireGuard 互操作，不等同于 Cloudflare 服务的实际账号/地域出口验证。健康检查可选真实 Cloudflare HTTPS，TLS 原字节透传，未伪造响应或证书。

在专用 Debian 12 测试环境安装 Rust、sing-box（本次 1.14.2）、iproute2、nftables、conntrack、wireguard-tools、dante-server、dnsmasq-base、dnsutils、curl、python3、util-linux。需要 root/CAP_NET_ADMIN、network/mount namespace、TUN 及内核 WireGuard。

~~~bash
cargo build --example netns_driver
work=$(mktemp -d /tmp/chainproxy-test.XXXXXX)
printf 'nameserver 192.0.2.1\n' > "$work/resolv.conf"
# 只在私有 mount namespace 内改变测试进程的 resolver。
sudo unshare -m sh -c '
  mount --bind "$1/resolv.conf" /etc/resolv.conf
  python3 tests/network_namespace.py \
    --driver target/debug/examples/netns_driver \
    --output "$1/results" --external-health
' sh "$work"
~~~

不提供 --external-health 时仍执行实际包转发、五模式、DNS、十次网络生命周期和超时恢复；提供该选项增加真实 engine commit/reload、十次完整事务、SIGKILL 持久快照恢复。额外 TLS relay 仅通过宿主机正常物理 socket 连接 1.1.1.1:443，不修改真实宿主机网络。--tools 可指向解包工具目录（默认 /usr）；远端验证采用解包依赖，未安装/启停该主机系统服务。

覆盖内容：

- Host/LAN 四种开关矩阵，LAN 到 Internet 和同 LAN 地址。
- IPv4/IPv6 Host/LAN 代理、外部 HTTP 从非直连地址访问 gateway 的物理回程。
- 0x400 路由查询与真实 WG 握手/转发，五种模式和 mixed SOCKS 测试端口。
- chain / physical / custom DNS 的 UDP、TCP listener 和 TUN DNS hijack。
- /25、/23、/16 实际接口前缀，以及外部 priority/table 占用拒绝。
- 第三方 conntrack 位保留，入站保留位清除。
- 10 次网络 start/stop，加 10 次完整 engine start/stop，逐次比较 rules/routes/nft/sysctl/TUN。
- 启动失败 watchdog、失败 reload 恢复旧配置、DNS endpoint 改 IP 后 reload。
- daemon SIGKILL、子进程清理、新实例读取持久 journal 恢复。
- 真实主机 main/rules/firewall 前后不变。

本次验证记录见 [routing-validation.txt](routing-validation.txt)。没有将 Rust 字符串单测称为互操作测试。

## 修改文件

| 文件 | 内容 |
|---|---|
| src/network/iproute.rs、nftables.rs、sysctl.rs、mod.rs | marks、独立 policy tables、实际前缀、nft route OUTPUT、sysctl 快照恢复 |
| src/network/gateway_monitor.rs、src/health/diagnose.rs | 新路由诊断、真实网段、两类出站状态 |
| src/singbox/generator.rs、process.rs | 关闭 auto_route、物理 DNS bootstrap、保留 detour、正常退出和父进程死亡清理 |
| src/engine/transaction.rs、history.rs | 持久网络快照、失败恢复、watchdog、确认提交落盘成功 |
| src/model/config.rs | forwarding 独立开关、mark 校验 |
| src/health/checker.rs | 去除以主机直连掩盖代理失败的 fallback |
| src/cli/menu.rs、src/api/router.rs | 真实前缀与开关状态，网关菜单同步 forwarding |
| examples/netns_driver.rs、tests/network_namespace.py、tests/tls_relay.py | 真实 Linux 隔离测试 |
| Cargo.toml、Cargo.lock、scripts/install.sh | Linux libc 父进程信号、conntrack 依赖 |
| .gitignore、README.md、docs/routing.md、docs/routing-validation.txt | 纳入测试、架构和测试记录 |

参考：[nftables chain 类型](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)、[sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/)、[sing-box Dial Fields](https://sing-box.sagernet.org/configuration/shared/dial/)、[sing-tun Linux 实现](https://github.com/SagerNet/sing-tun/blob/dev/tun_linux.go)、[conntrack 手册](https://netfilter.org/projects/conntrack-tools/conntrack-manpage.html)。

## v1.1.1 升级安装修复

修复安装脚本将 sing-box 的真实安装路径覆盖成自指软链接的问题，不再跨 /usr/bin 与 /usr/local/bin 重写 sing-box 文件。新二进制下载/编译并验证可执行后，先停止旧 chainproxy 服务，让 ExecStop 使用旧二进制完成清理，再替换程序。下载目标统一使用 latest Release。

v1.0.x 已经留下、且无快照归属信息的 auto_route 规则仍不会自动删除。错误现在包含具体地址族和冲突规则；需要结合旧 singbox_active.json、运行进程、TUN 状态核对后精确清理，不能仅按 table/priority 批量删除。CLI 不再无条件声称失败已回滚或 SSH 永不失联。

安装回归：在 Linux 执行 python3 tests/install_upgrade.py，验证既有 sing-box 文件不被替换、旧进程先停止、无效下载保持现有服务、停止失败禁止替换。
