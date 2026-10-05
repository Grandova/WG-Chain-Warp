use crate::network::sysctl::SysctlManager;
use std::process::Command;

pub struct GatewayMonitor;

impl GatewayMonitor {
    /// Generate a comprehensive, human-friendly, plain Chinese gateway diagnostic report
    pub fn generate_human_diagnostics(
        uplink: &str,
        subnets: &[String],
        local_ip: Option<&str>,
        gateway_enabled: bool,
    ) -> String {
        let mut report = String::new();
        report.push_str("==============================================================\n");
        report.push_str("              局域网透明网关诊断与体征报告 (人话版)           \n");
        report.push_str("==============================================================\n");

        if !gateway_enabled {
            report.push_str(" 🔴 网关功能当前处于 [关闭] 状态。\n");
            report.push_str(
                " 💡 若需让同局域网设备走本机代理，请在菜单中按 [8] -> [1] 开启网关功能。\n",
            );
            report.push_str("==============================================================\n");
            return report;
        }

        report.push_str(" 🟢 网关功能: 【已开启】\n");
        report.push_str(&format!(
            " 🌐 网关物理网卡: {} (本机 IP: {})\n",
            uplink,
            local_ip.unwrap_or("未检测到")
        ));
        report.push_str(&format!(" 🛡️ 允许通行的局域网网段: {:?}\n", subnets));
        report.push_str("--------------------------------------------------------------\n");
        report.push_str("【核心网络组件体征体检】\n");

        // 1. ip_forward check
        let ip_forward =
            SysctlManager::get("net.ipv4.ip_forward").unwrap_or_else(|| "0".to_string());
        if ip_forward == "1" {
            report.push_str(
                "  [OK] 1. 内核转发开关 (ip_forward): 🟢 正常开启 (已允许跨网卡数据中转)\n",
            );
        } else {
            report.push_str(
                "  [FAIL] 1. 内核转发开关 (ip_forward): ❌ 未开启 (局域网数据包无法被转发)\n",
            );
        }

        // 2. rp_filter check
        let rp_filter =
            SysctlManager::get("net.ipv4.conf.all.rp_filter").unwrap_or_else(|| "1".to_string());
        if rp_filter == "0" {
            report.push_str(
                "  [OK] 2. 反向路由过滤 (rp_filter): 🟢 已彻底关闭 (0，完全杜绝异步路由丢包)\n",
            );
        } else {
            report.push_str(&format!(
                "  [WARN] 2. 反向路由过滤 (rp_filter): ⚠️ 当前为 {} (建议为 0 避免偶发丢包)\n",
                rp_filter
            ));
        }

        // 3. Policy routing rule check (table 2022)
        let mut has_forward_rule = false;
        if let Ok(out) = Command::new("ip").args(["rule", "show"]).output() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for _subnet in subnets {
                if stdout
                    .lines()
                    .any(|l| l.contains("fwmark 0x1000/") && l.contains("lookup 2022"))
                {
                    has_forward_rule = true;
                    break;
                }
            }
        }
        if has_forward_rule {
            report.push_str(
                "  [OK] 3. 策略路由规则 (ip rule): 🟢 已就绪 (局域网数据包已定向导入代理表 2022)\n",
            );
        } else {
            report.push_str(
                "  [FAIL] 3. 策略路由规则 (ip rule): ❌ 未找到规则 (局域网流量未被引流至代理表)\n",
            );
        }

        // 4. Table 2022 default route check
        let mut has_tun_route = false;
        if let Ok(out) = Command::new("ip")
            .args(["route", "show", "table", "2022"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.lines().any(|l| l.starts_with("default dev chain0")) {
                has_tun_route = true;
            }
        }
        if has_tun_route {
            report.push_str(
                "  [OK] 4. 代理路由表 (table 2022): 🟢 已就绪 (默认出口指向 chain0 虚拟网卡)\n",
            );
        } else {
            report.push_str(
                "  [FAIL] 4. 代理路由表 (table 2022): ❌ 缺少出口 (table 2022 中未发现默认路由)\n",
            );
        }

        // 5. TUN interface chain0 check
        let mut tun_ok = false;
        let mut tun_rx = 0u64;
        let mut tun_tx = 0u64;
        if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
            for line in content.lines() {
                if line.contains("chain0:") {
                    tun_ok = true;
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 10 {
                        tun_rx = parts[1].parse().unwrap_or(0);
                        tun_tx = parts[9].parse().unwrap_or(0);
                    }
                    break;
                }
            }
        }
        if tun_ok {
            report.push_str(&format!(
                "  [OK] 5. 虚拟网卡 (chain0): 🟢 正常运行中 (已接收: {} 字节, 已发送: {} 字节)\n",
                tun_rx, tun_tx
            ));
        } else {
            report.push_str(
                "  [FAIL] 5. 虚拟网卡 (chain0): ❌ 网卡未创建 (sing-box 代理进程可能未正常运行)\n",
            );
        }

        // 6. Port 53 DNS listener check
        let mut dns_listening = false;
        if let Ok(out) = Command::new("ss").args(["-tulpn"]).output() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains(":53 ") || stdout.contains(":domain ") {
                dns_listening = true;
            }
        }
        if dns_listening {
            report.push_str(
                "  [OK] 6. DNS 监听端口 (Port 53): 🟢 正在监听服务 (支持接收局域网设备 DNS 查询)\n",
            );
        } else {
            report.push_str("  [WARN] 6. DNS 监听端口 (Port 53): ⚠️ 未检测到 53 端口监听 (公网 DNS 仍可通过 TUN 劫持解析)\n");
        }

        report.push_str("--------------------------------------------------------------\n");
        report.push_str("【📱 局域网客户端 (如另一台机器 / 手机 / 电脑) 正确配置方法】\n\n");
        let gw_ip = local_ip.unwrap_or("本机局域网IP");
        report.push_str("  1. IP 地址设置   : 手动指定 (Static IP)，例如同一子网的可用 IP\n");
        report.push_str("  2. 子网掩码     : 使用上方实际网段的 prefix length\n");
        report.push_str(&format!(
            "  3. 默认网关     : 【{}】 (必须填写本机的局域网 IP！)\n",
            gw_ip
        ));
        report.push_str(&format!(
            "  4. 首选 DNS      : 【{}】 或 【1.1.1.1】\n\n",
            gw_ip
        ));
        report.push_str("  ⚠️【最常见的没网/无法解析根源】:\n");
        report.push_str(
            "  许多用户把网关改成本机后，客户端的 DNS 依然留着旧路由器的 IP (如 10.82.160.1)。\n",
        );
        report.push_str(
            "  因为旧路由器和客户端在【同一个局域网内】，发往旧路由器的 DNS 根本不会走网关，\n",
        );
        report.push_str("  如果旧路由器无法联网，客户端就会立即报错: 'Could not resolve host'！\n");
        report.push_str(
            "  👉 解决办法：在客户端执行: echo 'nameserver 1.1.1.1' > /etc/resolv.conf\n",
        );
        report.push_str("==============================================================\n");

        report
    }

    /// Read the latest lines from singbox.log or system logs that relate to LAN client activity
    pub fn get_recent_lan_events(subnets: &[String], limit: usize) -> Vec<String> {
        let mut events = Vec::new();
        let log_path = std::path::Path::new("/var/lib/chainproxy/singbox.log");
        if !log_path.exists() {
            return events;
        }

        if let Ok(content) = std::fs::read_to_string(log_path) {
            let lines: Vec<&str> = content.lines().collect();
            let start = if lines.len() > 100 {
                lines.len() - 100
            } else {
                0
            };

            for line in lines[start..].iter().rev() {
                // Check if line mentions inbound or DNS or LAN IP
                let is_lan = subnets.iter().any(|s| {
                    let prefix = s.split('/').next().unwrap_or("");
                    let base: String = prefix
                        .chars()
                        .take(prefix.rfind('.').unwrap_or(0))
                        .collect();
                    !base.is_empty() && line.contains(&base)
                }) || line.contains("inbound")
                    || line.contains("dns")
                    || line.contains("tun-in")
                    || line.contains("dns-in");

                if is_lan {
                    events.push(line.to_string());
                    if events.len() >= limit {
                        break;
                    }
                }
            }
        }

        events.reverse();
        events
    }
}
