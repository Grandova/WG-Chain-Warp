use crate::error::{ChainError, Result};
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use tracing::{info, warn};

pub const INBOUND_FWMARK: u32 = 0x88;
pub const INBOUND_RULE_PRIORITY: u32 = 90;
pub const SSH_BYPASS_PRIORITY: u32 = 80;

#[derive(Debug, Clone)]
pub struct UplinkInfo {
    pub interface: String,
    pub gateway: String,
    pub local_ip: Option<IpAddr>,
}

pub struct IpRouteManager;

impl IpRouteManager {
    /// Detect default physical interface and gateway using `ip route show default`
    pub fn detect_default_uplink() -> Result<UplinkInfo> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| ChainError::CommandError {
                cmd: "ip route show default".to_string(),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(ChainError::NetworkError(
                "Failed to query default route via 'ip route show default'".to_string(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Typical output: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
        let line = stdout.lines().next().ok_or_else(|| {
            ChainError::NetworkError("No default route found in system routing table".to_string())
        })?;

        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut gateway = None;
        let mut interface = None;

        for i in 0..tokens.len() {
            if tokens[i] == "via" && i + 1 < tokens.len() {
                gateway = Some(tokens[i + 1].to_string());
            } else if tokens[i] == "dev" && i + 1 < tokens.len() {
                interface = Some(tokens[i + 1].to_string());
            }
        }

        let interface = interface.ok_or_else(|| {
            ChainError::NetworkError(format!("Could not determine uplink device from: {}", line))
        })?;
        let gateway = gateway.unwrap_or_default();

        let local_ip = Self::get_interface_ipv4(&interface).ok();

        Ok(UplinkInfo {
            interface,
            gateway,
            local_ip,
        })
    }

    /// Query primary IPv4 of an interface
    pub fn get_interface_ipv4(iface: &str) -> Result<IpAddr> {
        let output = Command::new("ip")
            .args(["-o", "-4", "addr", "show", "dev", iface])
            .output()
            .map_err(|e| ChainError::CommandError {
                cmd: format!("ip addr show {}", iface),
                message: e.to_string(),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            for (idx, token) in tokens.iter().enumerate() {
                if *token == "inet" && idx + 1 < tokens.len() {
                    let cidr = tokens[idx + 1];
                    let ip_str = cidr.split('/').next().unwrap_or("");
                    if let Ok(ip) = IpAddr::from_str(ip_str) {
                        return Ok(ip);
                    }
                }
            }
        }

        Err(ChainError::NetworkError(format!(
            "No IPv4 address assigned to interface '{}'",
            iface
        )))
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

    /// Add emergency SSH management bypass rule: `ip rule add to <client_ip> lookup main priority 80`
    pub fn add_ssh_emergency_bypass(client_ip: &IpAddr) -> Result<()> {
        let ip_str = client_ip.to_string();
        info!("Installing emergency SSH management bypass for {}", ip_str);

        // Delete existing rule at priority 80 if present to ensure idempotency
        let _ = Command::new("ip")
            .args(["rule", "del", "priority", &SSH_BYPASS_PRIORITY.to_string()])
            .output();

        let output = Command::new("ip")
            .args([
                "rule",
                "add",
                "to",
                &ip_str,
                "lookup",
                "main",
                "priority",
                &SSH_BYPASS_PRIORITY.to_string(),
            ])
            .output()
            .map_err(|e| ChainError::CommandError {
                cmd: "ip rule add to <ssh_ip>".to_string(),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            warn!("Failed to add SSH emergency bypass: {:?}", output.stderr);
        }

        Ok(())
    }

    /// Remove emergency SSH management bypass
    pub fn remove_ssh_emergency_bypass() {
        let _ = Command::new("ip")
            .args(["rule", "del", "priority", &SSH_BYPASS_PRIORITY.to_string()])
            .output();
    }

    /// Add inbound connection return rule: `ip rule add fwmark 0x88 lookup main priority 90`
    pub fn add_inbound_fwmark_rule(mark: u32, priority: u32) -> Result<()> {
        let mark_str = format!("{:#x}", mark);
        let prio_str = priority.to_string();

        // Idempotency check: remove first if already exists
        let _ = Command::new("ip")
            .args(["rule", "del", "priority", &prio_str])
            .output();

        let output = Command::new("ip")
            .args(["rule", "add", "fwmark", &mark_str, "lookup", "main", "priority", &prio_str])
            .output()
            .map_err(|e| ChainError::CommandError {
                cmd: format!("ip rule add fwmark {} lookup main priority {}", mark_str, prio_str),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(ChainError::NetworkError(format!(
                "Failed to add fwmark rule: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Remove inbound connection return rule
    pub fn remove_inbound_fwmark_rule(priority: u32) {
        let prio_str = priority.to_string();
        let _ = Command::new("ip")
            .args(["rule", "del", "priority", &prio_str])
            .output();
    }

    /// Add explicit host route for VPN1 endpoint on uplink: `ip route add <vpn1_ip> via <gw> dev <iface> table main`
    pub fn add_vpn1_endpoint_host_route(endpoint_ip: &str, gateway: &str, iface: &str) -> Result<()> {
        if endpoint_ip.is_empty() || gateway.is_empty() {
            return Ok(());
        }

        // Idempotency: delete first if already present
        let _ = Command::new("ip")
            .args(["route", "del", endpoint_ip, "dev", iface, "table", "main"])
            .output();

        let output = Command::new("ip")
            .args([
                "route", "add", endpoint_ip, "via", gateway, "dev", iface, "table", "main",
            ])
            .output()
            .map_err(|e| ChainError::CommandError {
                cmd: format!("ip route add {} via {}", endpoint_ip, gateway),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            warn!(
                "Notice adding VPN1 host route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Remove explicit host route for VPN1 endpoint
    pub fn remove_vpn1_endpoint_host_route(endpoint_ip: &str, iface: &str) {
        if !endpoint_ip.is_empty() {
            let _ = Command::new("ip")
                .args(["route", "del", endpoint_ip, "dev", iface, "table", "main"])
                .output();
        }
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
