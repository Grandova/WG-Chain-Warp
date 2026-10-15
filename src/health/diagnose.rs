use crate::network::iproute::IpRouteManager;
use crate::network::nftables::NftablesManager;
use crate::singbox::process::SingBoxManager;
use std::process::Command;

pub struct SystemDiagnostician;

impl SystemDiagnostician {
    /// Gather comprehensive, sanitized system diagnostic report
    pub fn generate_report(singbox_bin: &str) -> String {
        let mut out = String::new();
        out.push_str("=== SOOYA SYSTEM DIAGNOSTIC REPORT ===\n\n");

        // 1. OS & Kernel
        out.push_str("--- [1] Operating System & Kernel ---\n");
        if let Ok(uname) = Command::new("uname").arg("-a").output() {
            out.push_str(&format!(
                "Kernel: {}\n",
                String::from_utf8_lossy(&uname.stdout).trim()
            ));
        }
        if let Ok(os_rel) = std::fs::read_to_string("/etc/os-release") {
            let pretty = os_rel
                .lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .unwrap_or("PRETTY_NAME=Linux");
            out.push_str(&format!("OS: {}\n", pretty));
        }
        out.push('\n');

        // 2. Component Versions
        out.push_str("--- [2] Toolchain & Engine Versions ---\n");
        match SingBoxManager::probe_version(singbox_bin) {
            Ok(v) => out.push_str(&format!(
                "sing-box: {} (Supported: {})\n",
                v.version, v.is_supported
            )),
            Err(e) => out.push_str(&format!("sing-box: NOT FOUND ({})\n", e)),
        }
        match NftablesManager::probe_nftables() {
            Ok(v) => out.push_str(&format!("nftables: {}\n", v)),
            Err(e) => out.push_str(&format!("nftables: NOT FOUND ({})\n", e)),
        }
        if let Ok(ipr) = Command::new("ip").arg("-V").output() {
            out.push_str(&format!(
                "iproute2: {}\n",
                String::from_utf8_lossy(&ipr.stdout).trim()
            ));
        }
        let tun_ok = std::path::Path::new("/dev/net/tun").exists();
        out.push_str(&format!(
            "TUN device (/dev/net/tun): {}\n",
            if tun_ok {
                "EXISTS (OK)"
            } else {
                "NOT FOUND (Auto-creation supported)"
            }
        ));
        out.push('\n');

        // 3. Physical Network & Gateway
        out.push_str("--- [3] Uplink Physical Interface & Gateway ---\n");
        match IpRouteManager::detect_default_uplink() {
            Ok(up) => {
                out.push_str(&format!("Interface: {}\n", up.interface));
                out.push_str(&format!("Gateway: {}\n", up.gateway));
                out.push_str(&format!("Local IP: {:?}\n", up.local_ip));
            }
            Err(e) => out.push_str(&format!("Uplink detection failed: {}\n", e)),
        }
        out.push('\n');

        for (heading, args) in [
            ("MAIN ROUTE", vec!["route", "show", "table", "main"]),
            ("POLICY RULES", vec!["rule", "show"]),
            ("TABLE 2023", vec!["route", "show", "table", "2023"]),
            ("TUN", vec!["addr", "show", "dev", "chain0"]),
        ] {
            out.push_str(&format!("=== {} ===\n", heading));
            match Command::new("ip").arg("-4").args(&args).output() {
                Ok(result) => {
                    out.push_str(&String::from_utf8_lossy(&result.stdout));
                    out.push_str(&String::from_utf8_lossy(&result.stderr));
                }
                Err(e) => out.push_str(&format!("Unavailable: {}\n", e)),
            }
        }
        out.push_str("=== NFTABLES ===\n");
        match NftablesManager::list_table_rules() {
            Ok(rules) => {
                out.push_str(&format!(
                    "Host outbound: {}\n",
                    if rules.contains("host-proxy") {
                        "PROXY"
                    } else {
                        "DIRECT"
                    }
                ));
                out.push_str(&rules);
            }
            Err(e) => out.push_str(&format!("Unavailable: {}\n", e)),
        }
        use crate::network::iproute::{HOST_TABLE, MARK_INBOUND_RETURN, MARK_PHYSICAL_DIRECT};
        out.push_str(&format!(
            "Physical bypass mark: {:#x}\nInbound return mark: {:#x}\nHost proxy table: {}\n",
            MARK_PHYSICAL_DIRECT, MARK_INBOUND_RETURN, HOST_TABLE
        ));
        out.push_str("===========================================\n");

        out
    }
}
