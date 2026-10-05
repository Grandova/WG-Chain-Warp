# chainproxy REST API 文档

默认服务监听地址：`http://127.0.0.1:8880`

SOCKS5 服务端使用 `mode: "socks5_server"`，配置结构参见
[`examples/socks5-server.example.json`](../examples/socks5-server.example.json)。
`socks5_server.listen` 为本机 IPv4/IPv6 地址，`port` 为监听端口，`users` 为用户名/密码列表。
用户列表不能为空、用户名不能重复，用户名及密码各为 1–255 字节；修改后通过现有 apply 接口生效。
此模式使用本机直连出口，不启用透明代理路由或 LAN 网关。测试接口通过实际监听端口和首个用户认证，验证 DNS 和 HTTPS 出站。

---

## 1. 基础探活

### `GET /health`
- **说明**：用于负载均衡或监控系统的心跳探活。
- **返回**：`200 OK`，文本 `"OK"`。

---

## 2. 状态查询

### `GET /api/v1/status`
- **说明**：获取当前链式代理整体状态、版本、拓扑及分跳健康信息。
- **响应示例**：
```json
{
  "success": true,
  "data": {
    "state": "Running",
    "active_config_version": "20260927_214500",
    "uptime_seconds": 3600,
    "physical": {
      "interface": "eth0",
      "ip_addresses": ["185.58.159.235"],
      "gateway": "185.58.159.1",
      "status": "UP"
    },
    "vpn1": {
      "name": "VPN1",
      "endpoint": "198.51.100.1:51820",
      "config_valid": true,
      "reachable": true,
      "bytes_sent": 1048576,
      "bytes_received": 5242880,
      "latency_ms": 15,
      "status": "OK"
    },
    "vpn2": {
      "name": "Cloudflare WARP",
      "endpoint": "162.159.192.1:2408",
      "config_valid": true,
      "reachable": true,
      "bytes_sent": 1024000,
      "bytes_received": 5120000,
      "latency_ms": 28,
      "status": "OK (WARP Active)"
    },
    "final_hop": {
      "internet_ok": true,
      "exit_ip": "104.28.192.4",
      "exit_country": "Cloudflare",
      "exit_isp": "Cloudflare WARP",
      "latency_ms": 28,
      "status": "OK"
    },
    "chain_visual": "VPS [UP] -> VPN1 [OK] -> WARP [OK] -> Internet [OK]"
  }
}
```

---

## 3. 配置管理

### `GET /api/v1/config`
- **说明**：获取当前生效配置（所有 `PrivateKey` 与 `PresharedKey` 均脱敏为 `********`）。

### `POST /api/v1/config/validate`
- **说明**：仅验证用户提交的 JSON 与 WireGuard 配置合法性，不应用网络变更。
- **请求体**：
```json
{
  "config": {
    "enabled": true,
    "uplink_interface": "eth0",
    "vpn1": {
      "name": "VPN1",
      "wireguard_config": "[Interface]\nPrivateKey = ...\nAddress = 10.2.0.2/32\n\n[Peer]\nPublicKey = ...\nEndpoint = 198.51.100.1:51820\n"
    },
    "vpn2": {
      "name": "Cloudflare WARP",
      "wireguard_config": "[Interface]\nPrivateKey = ...\nAddress = 172.16.0.2/32\n\n[Peer]\nPublicKey = ...\nEndpoint = 162.159.192.1:2408\n"
    },
    "routing": {
      "proxy_host_outbound": true,
      "proxy_forwarded_outbound": true,
      "preserve_inbound_connections": true,
      "connection_mark": "0x88",
      "forwarded_subnets": ["10.0.0.0/24"]
    },
    "dns": {
      "mode": "chain"
    }
  }
}
```

### `POST /api/v1/config/apply`
- **说明**：事务式应用新配置，包含 SSH 保护、看门狗监控及自动回滚。

### `POST /api/v1/config/test`
- **说明**：发起分跳（Physical / VPN1 / WARP / Internet）链路性能与连通性测试。

---

## 4. 服务控制

### `POST /api/v1/start`
- **说明**：启动链式代理服务。

### `POST /api/v1/stop`
- **说明**：安全停止服务，原子性删除 `inet chainproxy` 表、策略路由及临时规则，恢复网络出厂状态。

### `POST /api/v1/restart`
- **说明**：重启服务。

### `POST /api/v1/rollback`
- **说明**：立即回滚到上一历史配置版本。

---

## 5. 诊断与日志

### `GET /api/v1/logs`
- **说明**：获取系统最近的运行日志。

### `GET /api/v1/network`
- **说明**：获取包含 OS、sing-box 版本、策略路由、nftables 规则在内的完整诊断报告。
