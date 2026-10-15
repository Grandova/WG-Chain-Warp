use crate::error::{ChainError, Result};
use crate::model::config::ChainProxyConfig;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::str::FromStr;
#[cfg(target_os = "linux")]
use tracing::info;

// Only these bits belong to Sooya; nft preserves all other mark bits.
pub const MARK_INBOUND_RETURN: u32 = 0x0088;
pub const MARK_PHYSICAL_DIRECT: u32 = 0x0400;
pub const MARK_HOST_PROXY: u32 = 0x0800;
pub const MARK_MASK: u32 = 0x0c88;
pub const DIRECT_RULE_PRIORITY: u32 = 70;
pub const SSH_BYPASS_PRIORITY: u32 = 80;
pub const INBOUND_RULE_PRIORITY: u32 = 90;
pub const LOCAL_RULE_PRIORITY: u32 = 100;
pub const HOST_RULE_PRIORITY: u32 = 120;
pub const HOST_TABLE: u32 = 2023;
pub const ROUTE_PROTOCOL: &str = "186";

#[derive(Debug, Clone)]
pub struct UplinkInfo {
    pub interface: String,
    pub gateway: String,
    pub local_ip: Option<IpAddr>,
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
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Execute multiple `ip` subcommands in a single `ip -batch -` invocation
    fn run_batch(commands: &[Vec<String>], force: bool) -> Result<()> {
        if commands.is_empty() {
            return Ok(());
        }
        let mut batch_script = String::with_capacity(commands.len() * 48);
        for cmd in commands {
            batch_script.push_str(&cmd.join(" "));
            batch_script.push('\n');
        }

        let mut ip_cmd = Command::new("ip");
        if force {
            ip_cmd.arg("-force");
        }
        ip_cmd
            .args(["-batch", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Ok(mut child) = ip_cmd.spawn() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(batch_script.as_bytes());
            }
            if let Ok(out) = child.wait_with_output() {
                if out.status.success() || force {
                    return Ok(());
                }
            }
        }

        // Fallback to sequential execution if `ip -batch` is unsupported
        for args in commands {
            let res = Self::run(&args.iter().map(String::as_str).collect::<Vec<_>>());
            if !force {
                res?;
            }
        }
        Ok(())
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

    pub fn route_plan(config: &ChainProxyConfig, ssh_ips: &[IpAddr]) -> Result<RoutePlan> {
        let mut plan = RoutePlan::default();
        let inbound = config.routing.inbound_mark()?;
        let mask = MARK_MASK | inbound;
        for family in ["-4", "-6"] {
            let ipv6 = family == "-6";
            let mut rules = vec![
                format!(
                    "priority {} fwmark {:#x}/{:#x} lookup main",
                    DIRECT_RULE_PRIORITY, MARK_PHYSICAL_DIRECT, MARK_PHYSICAL_DIRECT
                ),
                format!(
                    "priority {} fwmark {:#x}/{:#x} lookup main",
                    INBOUND_RULE_PRIORITY, inbound, inbound
                ),
            ];
            for ip in ssh_ips.iter().filter(|ip| ip.is_ipv6() == ipv6) {
                rules.push(format!(
                    "priority {} to {} lookup main",
                    SSH_BYPASS_PRIORITY, ip
                ));
            }
            if !ipv6 || config.routing.ipv6 {
                let mut bypass = config.routing.exclude_destinations.clone();
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
                if config.routing.proxy_host_outbound {
                    for subnet in bypass {
                        let net: IpNet = subnet.parse().map_err(|e: ipnet::AddrParseError| {
                            ChainError::ValidationError(e.to_string())
                        })?;
                        if net.addr().is_ipv6() == ipv6 {
                            rules.push(format!(
                                "priority {} fwmark {:#x}/{:#x} to {} lookup main",
                                LOCAL_RULE_PRIORITY,
                                MARK_HOST_PROXY,
                                mask,
                                net.trunc()
                            ));
                        }
                    }
                    rules.push(format!(
                        "priority {} fwmark {:#x}/{:#x} lookup main suppress_prefixlength 0",
                        LOCAL_RULE_PRIORITY + 1,
                        MARK_HOST_PROXY,
                        mask
                    ));
                    rules.push(format!(
                        "priority {} iif lo fwmark {:#x}/{:#x} lookup {}",
                        HOST_RULE_PRIORITY, MARK_HOST_PROXY, mask, HOST_TABLE
                    ));
                    rules.push(format!(
                        "priority {} iif lo fwmark {:#x}/{:#x} unreachable",
                        HOST_RULE_PRIORITY + 1,
                        MARK_HOST_PROXY,
                        mask
                    ));
                    plan.routes.push(
                        format!(
                            "{} route add default dev chain0 table {} proto {}",
                            family, HOST_TABLE, ROUTE_PROTOCOL
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

    /// Clean up any stale Sooya policy rules (proto 186 / table 2023) and orphaned chain0 device
    pub fn cleanup_stale() {
        for family in ["-4", "-6"] {
            let _ = Self::run(&[family, "route", "flush", "table", "2023"]);
            if let Ok(out) = Self::run(&[family, "-N", "-j", "rule", "show"]) {
                if let Ok(rules) = serde_json::from_str::<serde_json::Value>(&out) {
                    let mut del_cmds = Vec::new();
                    for rule in rules.as_array().into_iter().flatten() {
                        let is_sooya_proto = rule["protocol"].as_str() == Some(ROUTE_PROTOCOL)
                            || rule["protocol"].as_u64() == Some(186);
                        let is_sooya_table = rule["table"].as_u64() == Some(HOST_TABLE as u64)
                            || rule["table"].as_str() == Some("2023");
                        let prio = rule["priority"].as_u64().unwrap_or(0);
                        let is_sooya_prio = matches!(prio, 70 | 80 | 90 | 100 | 101 | 120 | 121);
                        if (is_sooya_proto || is_sooya_table || is_sooya_prio) && prio > 0 {
                            del_cmds.push(vec![
                                family.to_string(),
                                "rule".to_string(),
                                "del".to_string(),
                                "priority".to_string(),
                                prio.to_string(),
                            ]);
                        }
                    }
                    let _ = Self::run_batch(&del_cmds, true);
                }
            }
        }
        if Self::interface_exists("chain0") {
            let _ = Self::run(&["link", "del", "dev", "chain0"]);
        }
    }

    pub fn check_available(plan: &RoutePlan) -> Result<()> {
        Self::cleanup_stale();
        for family in ["-4", "-6"] {
            let Ok(rules_raw) = Self::run(&[family, "-N", "-j", "rule", "show"]) else {
                if family == "-6" {
                    continue;
                }
                return Err(ChainError::NetworkError("Failed to inspect IPv4 policy rules".into()));
            };
            let rules: serde_json::Value =
                serde_json::from_str(&rules_raw).unwrap_or_else(|_| serde_json::json!([]));
            for rule in rules.as_array().into_iter().flatten() {
                if rule["table"].as_u64() == Some(HOST_TABLE as u64)
                    || rule["table"].as_str() == Some(&HOST_TABLE.to_string())
                {
                    return Err(ChainError::NetworkError(format!(
                        "Existing {} policy rule references table {}: {}",
                        family, HOST_TABLE, rule
                    )));
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
            // Note: `ip -6 route show table 2023` returns exit code 2 ("Error: ipv6: FIB table does not exist")
            // when table 2023 has not been allocated in the kernel yet. That means table 2023 is empty and available!
            if let Ok(routes_raw) = Self::run(&[family, "-N", "-j", "route", "show", "table", "2023"]) {
                let routes: serde_json::Value =
                    serde_json::from_str(&routes_raw).unwrap_or_else(|_| serde_json::json!([]));
                if routes.as_array().map(|arr| !arr.is_empty()).unwrap_or(false) {
                    return Err(ChainError::NetworkError(
                        "Routing table 2023 already in use; stop its owner before applying".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn install_rules(plan: &RoutePlan) -> Result<()> {
        let (v4, v6): (Vec<_>, Vec<_>) = plan.rules.iter().cloned().partition(|r| r.first().map(String::as_str) != Some("-6"));
        Self::run_batch(&v4, false)?;
        let _ = Self::run_batch(&v6, true);
        Ok(())
    }

    pub fn install_routes(plan: &RoutePlan) -> Result<()> {
        let (v4, v6): (Vec<_>, Vec<_>) = plan.routes.iter().cloned().partition(|r| r.first().map(String::as_str) != Some("-6"));
        Self::run_batch(&v4, false)?;
        let _ = Self::run_batch(&v6, true);
        Ok(())
    }

    pub fn remove_plan(plan: &RoutePlan) -> Result<()> {
        let mut del_cmds = Vec::with_capacity(plan.rules.len() + plan.routes.len());
        for args in plan.rules.iter().rev().chain(plan.routes.iter().rev()) {
            let mut del_args = args.clone();
            if del_args.len() > 2 {
                del_args[2] = "del".to_string();
            }
            del_cmds.push(del_args);
        }
        let _ = Self::run_batch(&del_cmds, true);
        Self::cleanup_stale();
        Ok(())
    }

    pub fn interface_exists(name: &str) -> bool {
        #[cfg(target_os = "linux")]
        {
            if std::path::Path::new(&format!("/sys/class/net/{}", name)).exists() {
                return true;
            }
        }
        Self::run(&["link", "show", "dev", name]).is_ok()
    }

    pub fn wait_for_interface(name: &str, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if Self::interface_exists(name) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    /// Detect active SSH client IP addresses from environment ($SSH_CONNECTION / $SSH_CLIENT)
    pub fn detect_current_ssh_client_ips() -> Vec<IpAddr> {
        let mut ips = Vec::new();
        for var in ["SSH_CONNECTION", "SSH_CLIENT"] {
            if let Ok(val) = std::env::var(var) {
                if let Some(ip_str) = val.split_whitespace().next() {
                    if let Ok(ip) = IpAddr::from_str(ip_str) {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
        ips
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
            let _ = Command::new("modprobe").arg("tun").output();
            let _ = std::fs::create_dir_all("/dev/net");
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
                "系统缺少 TUN 设备 (/dev/net/tun) 且自动创建失败。请确认宿主机已开启 TUN 模块权限。"
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
    fn host_switch_manages_table_2023() {
        for host in [false, true] {
            let mut config = ChainProxyConfig::default();
            config.routing.proxy_host_outbound = host;
            let plan = IpRouteManager::route_plan(&config, &[]).unwrap();
            assert_eq!(
                plan.routes.iter().any(|r| r.contains(&"2023".to_string())),
                host
            );
            assert!(plan.routes.iter().all(|r| !r.contains(&"main".to_string())));
            assert!(plan
                .rules
                .iter()
                .filter(|r| r.contains(&"2023".to_string()))
                .all(|r| r.windows(2).any(|w| w == ["iif", "lo"])));
        }
    }

    #[test]
    fn custom_inbound_mark_and_both_ssh_families_are_preserved() {
        let mut config = ChainProxyConfig::default();
        config.routing.connection_mark = "0x20".to_string();
        let plan = IpRouteManager::route_plan(
            &config,
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
        for mark in ["0", "0x400", "0x800", "invalid"] {
            config.routing.connection_mark = mark.to_string();
            assert!(IpRouteManager::route_plan(&config, &[]).is_err());
        }
    }
}
