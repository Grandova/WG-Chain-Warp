# chainproxy 安全策略与事务回滚机制

## 1. 密钥与凭据安全 (Secret Redaction)

1. **API 脱敏**：
   - `GET /api/v1/config`、`chainproxy status` 和 `chainproxy diagnose` 严禁输出明文私钥。
   - 所有 `PrivateKey` 和 `PresharedKey` 均替换为 `********`。
2. **文件权限保护**：
   - 存储目录 `/var/lib/chainproxy` 权限设为 `0700`。
   - 生成的配置文件和版本历史文件权限为 `0600`。
3. **日志脱敏**：
   - `tracing` 日志系统拦截并过滤所有敏感字段，控制台输出绝不泄露私钥。

---

## 2. 严禁执行 PostUp / PostDown

传统 WireGuard 配置中常包含：
```ini
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostDown = ...
```
**安全禁令**：`chainproxy` 解析器支持识别这些字段用于用户界面展示或审计，但**绝对禁止**调用 `sh -c`、`bash -c` 或 `eval` 执行用户提供的脚本代码，从根本上防止远程代码执行（RCE）漏洞。

---

## 3. SSH 零失联保护流程

网络重配置最致命的风险是导致管理员 SSH 断线且无法重连。`chainproxy` 采用多层安全兜底：

```
[检测 SSH 会话] -> 获取来源 IP (如 $SSH_CONNECTION)
       │
       ▼
[创建临时管理白名单] -> ip rule add to <client_ip> lookup main priority 80
       │
       ▼
[应用网络变更] -> 启动 sing-box + 设置 inet chainproxy
       │
       ▼
[启动 30 秒看门狗] -> Watchdog 倒计时开始
       │
       ▼
[全链路健康探测] ───(失败/超时)───> [自动 ROLLBACK: 恢复上一版/清理白名单]
       │
     (成功)
       ▼
[转正与提交] -> 取消看门狗, 转为正式 conntrack mark 0x88 保护
```

---

## 4. 事务生命周期 (Transaction Pipeline)

每次执行 `chainproxy apply` 必须走完 8 个阶段：
1. **VALIDATE**：
   - 检查 WireGuard 私钥与公钥的 Base64 格式（严格解码为 32 字节）。
   - 校验 IP、CIDR 范围与 Endpoint 端口（1..=65535）。
   - 校验 sing-box 版本支持情况（>= 1.14）。
2. **SNAPSHOT**：
   - 备份当前运行配置至历史版本队列（保留最近 10 个版本）。
3. **GENERATE**：
   - 动态生成 sing-box JSON 与 `inet chainproxy` 表规则。
4. **CHECK**：
   - 调用 `sing-box check -c <temp_file>` 做原生语法检查，有报错立刻中止。
5. **SAFETY**：
   - 注入 SSH 应急白名单路由（`priority 80`）。
6. **APPLY**：
   - 调整系统 sysctl 参数（`rp_filter=2`，`ip_forward=1`）。
   - 原子加载 `inet chainproxy` 表。
   - 插入回程策略路由 `ip rule add fwmark 0x88 lookup main priority 90`。
   - 添加 VPN1 端点主机明细路由。
   - 启动 sing-box 进程。
7. **WATCHDOG**：
   - 独立后台看门狗定时器就绪。
8. **TEST & COMMIT**：
   - 发起本地代理探测：Direct -> VPN1 -> WARP -> Internet。
   - 成功：提交版本为 `last_known_good`，撤除临时白名单，取消看门狗。
   - 失败：自动触发回滚恢复。

---

## 5. 幂等性与清理保障

- **隔离表空间**：所有规则集中在自定义表 `table inet chainproxy` 中。
- **严禁全量刷新**：严禁执行 `nft flush ruleset` 或清空其他表。
- **所有规则打标**：所有 nftables 规则均包含 `comment "chainproxy-managed"`。
- **安全停止 (`chainproxy stop`)**：
  1. 停止 sing-box 进程；
  2. 执行 `nft delete table inet chainproxy`；
  3. 删除 `priority 90` 的 `fwmark 0x88` 规则；
  4. 删除 VPN1 端点主机明细路由；
  5. 恢复 sysctl 初始快照值。
- **重复执行保证**：连续执行 10 次 `apply`，规则结构绝对确定，绝不产生多余或重复的策略路由和防火墙条目。
