use crate::error::{ChainError, Result};
use crate::model::config::ChainProxyConfig;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;
use std::str::FromStr;
#[cfg(target_os = "linux")]
use tracing::info;

// Only these bits belong to chainproxy; nft preserves all other mark bits.
pub const MARK_INBOUND_RETURN: u32 = 0x0088;
pub const MARK_PHYSICAL_DIRECT: u32 = 0x0400;
pub const MARK_HOST_PROXY: u32 = 0x0800;
pub const MARK_FORWARD_PROXY: u32 = 0x1000;
pub const MARK_MASK: u32 = 0x1c88;
pub const DIRECT_RULE_PRIORITY: u32 = 70;
pub const SSH_BYPASS_PRIORITY: u32 = 80;
pub const INBOUND_RULE_PRIORITY: u32 = 90;
pub const LOCAL_RULE_PRIORITY: u32 = 100;
pub const FORWARD_RULE_PRIORITY: u32 = 110;
pub const HOST_RULE_PRIORITY: u32 = 120;
pub const FORWARD_TABLE: u32 = 2022;
pub const HOST_TABLE: u32 = 2023;
pub const ROUTE_PROTOCOL: &str = "186";

#[derive(Debug, Clone)]
pub struct UplinkInfo {
    pub interface: String,
    pub gateway: String,
    pub local_ip: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanSubnet {
    pub interface: String,
    pub subnet: IpNet,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutePlan {
    pub rules: Vec<Vec<String>>,
    pub routes: Vec<Vec<String>>,
}

pub struct IpRouteManager;

impl IpRouteManager {
    pub fn run(args: &[&str]) -> Result<String> {
        let output = Command::new("ip").args(args).output()?;
        if !output.status.success() {
            return Err(ChainError::NetworkError(format!(
                "ip {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub fn detect_default_uplink() -> Result<UplinkInfo> {
        let routes: serde_json::Value = serde_json::from_str(&Self::run(&[
            "-j", "route", "show", "table", "main", "default",
        ])?)?;
        let route = routes.as_array().and_then(|r| r.first()).ok_or_else(|| {
            ChainError::NetworkError("No physical default route in main".to_string())
        })?;
        let interface = route["dev"]
            .as_str()
            .ok_or_else(|| ChainError::NetworkError("Default route has no interface".to_string()))?
            .to_string();
        Ok(UplinkInfo {
            local_ip: Self::get_interface_ipv4(&interface).ok(),
            interface,
            gateway: route["gateway"].as_str().unwrap_or("").to_string(),
        })
    }

    pub fn get_interface_ipv4(iface: &str) -> Result<IpAddr> {
        let data: serde_json::Value =
            serde_json::from_str(&Self::run(&["-j", "-4", "addr", "show", "dev", iface])?)?;
        data.as_array()
            .into_iter()
            .flatten()
            .flat_map(|i| i["addr_info"].as_array().into_iter().flatten())
            .find_map(|a| a["local"].as_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| ChainError::NetworkError(format!("No IPv4 address on {}", iface)))
    }

    pub fn interface_subnets(iface: &str) -> Result<Vec<IpNet>> {
        let data: serde_json::Value =
            serde_json::from_str(&Self::run(&["-j", "addr", "show", "dev", iface])?)?;
        let mut subnets = Vec::new();
        for addr in data
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|i| i["addr_info"].as_array().into_iter().flatten())
        {
            if addr["scope"] != "global" {
                continue;
            }
            if let (Some(ip), Some(prefix)) = (addr["local"].as_str(), addr["prefixlen"].as_u64()) {
                let net = format!("{}/{}", ip, prefix)
                    .parse::<IpNet>()
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?
                    .trunc();
                if !subnets.contains(&net) {
                    subnets.push(net);
                }
            }
        }
        Ok(subnets)
    }

    pub fn get_interface_lan_subnet(iface: &str) -> Option<String> {
        Self::interface_subnets(iface)
            .ok()?
            .into_iter()
            .find(|s| s.addr().is_ipv4())
            .map(|s| s.to_string())
    }

    pub fn detect_default_lan_subnet() -> Option<(String, String)> {
        let uplink = Self::detect_default_uplink().ok()?;
        let subnet = Self::get_interface_lan_subnet(&uplink.interface)?;
        Some((uplink.interface, subnet))
    }

    pub fn lan_subnets(config: &ChainProxyConfig, uplink: &str) -> Result<Vec<LanSubnet>> {
        let mut subnets = config.get_effective_forwarded_subnets(None);
        if config.gateway.enabled && config.gateway.auto_allow_lan {
            for subnet in Self::interface_subnets(uplink)? {
                if subnet.addr().is_ipv4() || config.routing.ipv6 {
                    subnets.push(subnet.to_string());
                }
            }
        }
        let mut result = Vec::new();
        for subnet in subnets {
            let subnet = subnet
                .parse::<IpNet>()
                .map_err(|e| ChainError::ValidationError(e.to_string()))?
                .trunc();
            if subnet.addr().is_ipv6() && !config.routing.ipv6 {
                continue;
            }
            if result.iter().any(|s: &LanSubnet| s.subnet == subnet) {
                continue;
            }
            let family = if subnet.addr().is_ipv4() { "-4" } else { "-6" };
            // Consult main directly so an active proxy configuration cannot change LAN discovery.
            let routes: serde_json::Value = serde_json::from_str(&Self::run(&[
                family,
                "-j",
                "route",
                "show",
                "table",
                "main",
                "match",
                &subnet.addr().to_string(),
            ])?)?;
            let route = routes
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| {
                    r["dev"].as_str().is_some_and(|dev| dev != "chain0")
                        && r["dst"]
                            .as_str()
                            .and_then(|s| s.parse::<IpNet>().ok())
                            .is_some_and(|net| {
                                net.prefix_len() <= subnet.prefix_len()
                                    && net.contains(&subnet.addr())
                            })
                })
                .max_by_key(|r| {
                    r["dst"]
                        .as_str()
                        .and_then(|s| s.parse::<IpNet>().ok())
                        .map(|net| {
                            (
                                net.prefix_len(),
                                std::cmp::Reverse(r["metric"].as_u64().unwrap_or(0)),
                            )
                        })
                });
            let interface = route.and_then(|r| r["dev"].as_str()).ok_or_else(|| {
                ChainError::ValidationError(format!(
                    "LAN subnet {} has no non-default route in main",
                    subnet
                ))
            })?;
            result.push(LanSubnet {
                interface: interface.to_string(),
                subnet,
            });
        }
        Ok(result)
    }

    pub fn route_plan(
        config: &ChainProxyConfig,
        lans: &[LanSubnet],
        ssh_ips: &[IpAddr],
    ) -> Result<RoutePlan> {
        let mut plan = RoutePlan::default();
        let inbound = config.routing.inbound_mark()?;
        let mask = MARK_MASK | inbound;
        for family in ["-4", "-6"] {
            let ipv6 = family == "-6";
            let mut rules = vec![format!(
                "priority {} fwmark {:#x}/{:#x} lookup main",
                DIRECT_RULE_PRIORITY, MARK_PHYSICAL_DIRECT, MARK_PHYSICAL_DIRECT
            )];
            if config.routing.preserve_inbound_connections {
                rules.push(format!(
                    "priority {} fwmark {:#x}/{:#x} lookup main",
                    INBOUND_RULE_PRIORITY, inbound, inbound
                ));
                for ip in ssh_ips.iter().filter(|ip| ip.is_ipv6() == ipv6) {
                    rules.push(format!(
                        "priority {} to {} lookup main",
                        SSH_BYPASS_PRIORITY, ip
                    ));
                }
            }
            if !ipv6 || config.routing.ipv6 {
                let mut bypass = config.routing.exclude_destinations.clone();
                bypass.extend(lans.iter().map(|s| s.subnet.to_string()));
                bypass.extend(
                    [
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "127.0.0.0/8",
                        "169.254.0.0/16",
                        "224.0.0.0/4",
                        "255.255.255.255/32",
                        "::1/128",
                        "fe80::/10",
                        "fc00::/7",
                        "ff00::/8",
                    ]
                    .map(str::to_string),
                );
                bypass.sort();
                bypass.dedup();
                for subnet in bypass {
                    let net: IpNet = subnet.parse().map_err(|e: ipnet::AddrParseError| {
                        ChainError::ValidationError(e.to_string())
                    })?;
                    if net.addr().is_ipv6() == ipv6 {
                        for (enabled, mark) in [
                            (config.routing.proxy_host_outbound, MARK_HOST_PROXY),
                            (
                                config.is_forwarding_enabled() && !lans.is_empty(),
                                MARK_FORWARD_PROXY,
                            ),
                        ] {
                            if enabled {
                                rules.push(format!(
                                    "priority {} fwmark {:#x}/{:#x} to {} lookup main",
                                    LOCAL_RULE_PRIORITY,
                                    mark,
                                    mask,
                                    net.trunc()
                                ));
                            }
                        }
                    }
                }
                for (enabled, mark, table, priority) in [
                    (
                        config.is_forwarding_enabled()
                            && lans.iter().any(|s| s.subnet.addr().is_ipv6() == ipv6),
                        MARK_FORWARD_PROXY,
                        FORWARD_TABLE,
                        FORWARD_RULE_PRIORITY,
                    ),
                    (
                        config.routing.proxy_host_outbound,
                        MARK_HOST_PROXY,
                        HOST_TABLE,
                        HOST_RULE_PRIORITY,
                    ),
                ] {
                    if !enabled {
                        continue;
                    }
                    rules.push(format!(
                        "priority {} fwmark {:#x}/{:#x} lookup main suppress_prefixlength 0",
                        LOCAL_RULE_PRIORITY + 1,
                        mark,
                        mask
                    ));
                    let selector = if mark == MARK_HOST_PROXY {
                        "iif lo "
                    } else {
                        ""
                    };
                    rules.push(format!(
                        "priority {} {}fwmark {:#x}/{:#x} lookup {}",
                        priority, selector, mark, mask, table
                    ));
                    // Fail closed if the TUN disappears; selected proxy flows must not leak to main.
                    rules.push(format!(
                        "priority {} {}fwmark {:#x}/{:#x} unreachable",
                        priority + 1,
                        selector,
                        mark,
                        mask
                    ));
                    plan.routes.push(
                        format!(
                            "{} route add default dev chain0 table {} proto {}",
                            family, table, ROUTE_PROTOCOL
                        )
                        .split_whitespace()
                        .map(str::to_string)
                        .collect(),
                    );
                }
            }
            for rule in rules {
                plan.rules.push(
                    format!("{} rule add {} protocol {}", family, rule, ROUTE_PROTOCOL)
                        .split_whitespace()
                        .map(str::to_string)
                        .collect(),
                );
            }
        }
        Ok(plan)
    }

    pub fn check_available(plan: &RoutePlan) -> Result<()> {
        for family in ["-4", "-6"] {
            let rules: serde_json::Value =
                serde_json::from_str(&Self::run(&[family, "-N", "-j", "rule", "show"])?)?;
            for rule in rules.as_array().into_iter().flatten() {
                if [FORWARD_TABLE, HOST_TABLE].iter().any(|t| {
                    rule["table"].as_u64() == Some(*t as u64)
                        || rule["table"].as_str() == Some(&t.to_string())
                }) {
                    return Err(ChainError::NetworkError("An existing policy rule references table 2022/2023; stop its owner before applying".to_string()));
                }
                if let Some(priority) = rule["priority"].as_u64() {
                    if plan
                        .rules
                        .iter()
                        .any(|r| r[0] == family && r[4] == priority.to_string())
                    {
                        return Err(ChainError::NetworkError(format!(
                            "Reserved policy priority {} already in use ({})",
                            priority, family
                        )));
                    }
                }
            }
            let routes: serde_json::Value = serde_json::from_str(&Self::run(&[
                family, "-N", "-j", "route", "show", "table", "all",
            ])?)?;
            for route in routes.as_array().into_iter().flatten() {
                if [FORWARD_TABLE, HOST_TABLE].iter().any(|t| {
                    route["table"].as_u64() == Some(*t as u64)
                        || route["table"].as_str() == Some(&t.to_string())
                }) {
                    return Err(ChainError::NetworkError(
                        "Routing table 2022/2023 already in use; stop its owner before applying"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn install_rules(plan: &RoutePlan) -> Result<()> {
        for args in &plan.rules {
            Self::run(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
        }
        Ok(())
    }

    pub fn install_routes(plan: &RoutePlan) -> Result<()> {
        for args in &plan.routes {
            Self::run(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
        }
        Ok(())
    }

    pub fn remove_plan(plan: &RoutePlan) -> Result<()> {
        let mut failure = None;
        for args in plan.rules.iter().rev().chain(plan.routes.iter().rev()) {
            let mut args = args.clone();
            args[2] = "del".to_string();
            let output = Command::new("ip").args(&args).output()?;
            let error = String::from_utf8_lossy(&output.stderr);
            if !output.status.success()
                && !error.contains("No such")
                && !error.contains("Cannot find device")
                && !error.contains("Cannot find specified")
            {
                failure = Some(ChainError::NetworkError(format!(
                    "ip {}: {}",
                    args.join(" "),
                    error
                )));
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    pub fn wait_for_interface(name: &str, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if Self::run(&["link", "show", "dev", name]).is_ok() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        false
    }

    /// Detect active SSH client IP addresses from environment ($SSH_CONNECTION / $SSH_CLIENT)
    pub fn detect_current_ssh_client_ips() -> Vec<IpAddr> {
        let mut ips = Vec::new();

        if let Ok(ssh_conn) = std::env::var("SSH_CONNECTION") {
            // SSH_CONNECTION="<client_ip> <client_port> <server_ip> <server_port>"
            if let Some(client_ip_str) = ssh_conn.split_whitespace().next() {
                if let Ok(ip) = IpAddr::from_str(client_ip_str) {
                    ips.push(ip);
                }
            }
        }

        if let Ok(ssh_client) = std::env::var("SSH_CLIENT") {
            // SSH_CLIENT="<client_ip> <client_port> <server_port>"
            if let Some(client_ip_str) = ssh_client.split_whitespace().next() {
                if let Ok(ip) = IpAddr::from_str(client_ip_str) {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }

        ips
    }

    /// Resolve a hostname or IP string to a list of IpAddr
    pub fn resolve_host_to_ips(host: &str) -> Vec<IpAddr> {
        let clean = host.trim();
        if clean.is_empty() {
            return Vec::new();
        }
        if let Ok(ip) = clean.parse::<IpAddr>() {
            return vec![ip];
        }
        let socket_str = format!("{}:0", clean);
        if let Ok(addrs) = socket_str.to_socket_addrs() {
            let mut ips: Vec<IpAddr> = Vec::new();
            for addr in addrs {
                let ip = addr.ip();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            if !ips.is_empty() {
                return ips;
            }
        }
        Vec::new()
    }

    /// Check and automatically create /dev/net/tun if missing
    pub fn ensure_tun_device() -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let tun_path = std::path::Path::new("/dev/net/tun");
            if tun_path.exists() {
                return Ok(());
            }

            info!("TUN device /dev/net/tun not found, attempting auto-creation...");
            // 1. Try modprobe tun (Linux kernel module)
            let _ = Command::new("modprobe").arg("tun").output();

            // 2. Ensure parent directory /dev/net exists
            let _ = std::fs::create_dir_all("/dev/net");

            // 3. Create TUN character device (major 10, minor 200)
            let status = Command::new("mknod")
                .args(["/dev/net/tun", "c", "10", "200"])
                .status();

            if status.map(|s| s.success()).unwrap_or(false) {
                let _ = Command::new("chmod").args(["666", "/dev/net/tun"]).status();
            }

            if tun_path.exists() {
                info!("Successfully created /dev/net/tun character device.");
                return Ok(());
            }

            Err(ChainError::NetworkError(
                "系统缺少 TUN 设备 (/dev/net/tun) 且自动创建失败。\n\
                 可能原因与排查方案：\n\
                 1. 若运行在 Incus / LXC 容器环境：请在宿主机执行：\n\
                    incus config device add <容器名> tun unix-char path=/dev/net/tun\n\
                    (或 lxc config device add <容器名> tun unix-char path=/dev/net/tun)\n\
                 2. 若运行在 Docker 容器：请在启动命令中添加：\n\
                    --device /dev/net/tun --cap-add=NET_ADMIN\n\
                 3. 若运行在物理机/常规 VPS：请以 root 权限执行：\n\
                    mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun"
                    .to_string(),
            ))
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_forward_switches_have_separate_tables() {
        let lan = LanSubnet {
            interface: "lan0".to_string(),
            subnet: "198.18.0.128/25".parse().unwrap(),
        };
        for host in [false, true] {
            for forward in [false, true] {
                let mut config = ChainProxyConfig::default();
                config.gateway.enabled = true;
                config.routing.proxy_host_outbound = host;
                config.routing.proxy_forwarded_outbound = forward;
                let plan =
                    IpRouteManager::route_plan(&config, std::slice::from_ref(&lan), &[]).unwrap();
                assert_eq!(
                    plan.routes.iter().any(|r| r.contains(&"2023".to_string())),
                    host
                );
                assert_eq!(
                    plan.routes.iter().any(|r| r.contains(&"2022".to_string())),
                    forward
                );
                assert!(plan.routes.iter().all(|r| !r.contains(&"main".to_string())));
                assert!(plan
                    .rules
                    .iter()
                    .filter(|r| r.contains(&"2023".to_string()))
                    .all(|r| r.windows(2).any(|w| w == ["iif", "lo"])));
            }
        }
    }

    #[test]
    fn custom_inbound_mark_and_both_ssh_families_are_preserved() {
        let mut config = ChainProxyConfig::default();
        config.routing.connection_mark = "0x20".to_string();
        let plan = IpRouteManager::route_plan(
            &config,
            &[],
            &[
                "198.51.100.9".parse().unwrap(),
                "2001:db8::9".parse().unwrap(),
            ],
        )
        .unwrap();
        for family in ["-4", "-6"] {
            assert!(plan
                .rules
                .iter()
                .any(|r| r[0] == family && r.contains(&"0x20/0x20".to_string())));
            assert!(plan
                .rules
                .iter()
                .any(|r| r[0] == family && r.contains(&"80".to_string())));
        }
        for mark in ["0", "0x400", "0x800", "0x1000", "invalid"] {
            config.routing.connection_mark = mark.to_string();
            assert!(IpRouteManager::route_plan(&config, &[], &[]).is_err());
        }
    }
}
