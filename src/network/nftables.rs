use crate::error::{ChainError, Result};
use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{info, warn};

pub const TABLE_NAME: &str = "chainproxy";
pub const TABLE_FAMILY: &str = "inet";
pub const RULE_COMMENT: &str = "chainproxy-managed";

pub struct NftablesManager;

impl NftablesManager {
    pub fn generate_ruleset(
        config: &crate::model::config::ChainProxyConfig,
        lans: &[crate::network::iproute::LanSubnet],
    ) -> Result<String> {
        use crate::network::iproute::{
            MARK_FORWARD_PROXY, MARK_HOST_PROXY, MARK_MASK, MARK_PHYSICAL_DIRECT,
        };
        let inbound = config.routing.inbound_mark()?;
        let mask = MARK_MASK | inbound;
        let keep = !mask;
        let mut script =
            "add table inet chainproxy\nflush table inet chainproxy\ntable inet chainproxy {\n"
                .to_string();
        script.push_str("    chain prerouting {\n        type filter hook prerouting priority mangle; policy accept;\n");
        if config.routing.preserve_inbound_connections {
            // Direction matters: replies to our own physical sockets must not become inbound connections.
            script.push_str(&format!("        iifname != \"chain0\" iifname != \"lo\" fib daddr type local ct direction original ct state new,established ct mark & {mask:#x} == 0 ct mark set ct mark | {inbound:#x} counter comment \"inbound-return\"\n"));
        }
        script.push_str("        fib daddr type local return\n");
        if config.is_forwarding_enabled() {
            for lan in lans {
                let family = if lan.subnet.addr().is_ipv4() {
                    "ip"
                } else {
                    "ip6"
                };
                let iface = serde_json::to_string(&lan.interface)?;
                script.push_str(&format!("        iifname {iface} {family} saddr {} meta mark & {mask:#x} == 0 meta mark set (meta mark & {keep:#x}) | {MARK_FORWARD_PROXY:#x} counter comment \"lan-proxy\"\n", lan.subnet));
            }
        }
        script.push_str("    }\n    chain output {\n        type route hook output priority mangle; policy accept;\n");
        script.push_str(&format!(
            "        meta mark & {MARK_PHYSICAL_DIRECT:#x} != 0 counter return\n"
        ));
        if config.routing.preserve_inbound_connections {
            script.push_str(&format!("        ct direction reply ct mark & {inbound:#x} == {inbound:#x} meta mark set (meta mark & {keep:#x}) | {inbound:#x} counter return\n"));
        }
        script.push_str("        fib daddr type local return\n");
        if config.routing.proxy_host_outbound {
            let family = if config.routing.ipv6 {
                ""
            } else {
                "meta nfproto ipv4 "
            };
            script.push_str(&format!("        {family}meta mark & {mask:#x} == 0 meta mark set (meta mark & {keep:#x}) | {MARK_HOST_PROXY:#x} counter comment \"host-proxy\"\n"));
        }
        script.push_str("    }\n");
        if config.is_forwarding_enabled() && !lans.is_empty() {
            script.push_str("    chain forward {\n        type filter hook forward priority filter; policy accept;\n");
            // Clamp before any accepting verdict, including retransmitted SYNs.
            script.push_str("        oifname \"chain0\" tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu\n");
            script.push_str("        iifname \"chain0\" tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu\n");
            script.push_str(
                "        iifname \"chain0\" ct state established,related counter accept\n",
            );
            for lan in lans {
                let family = if lan.subnet.addr().is_ipv4() {
                    "ip"
                } else {
                    "ip6"
                };
                let iface = serde_json::to_string(&lan.interface)?;
                script.push_str(&format!(
                    "        iifname {iface} {family} saddr {} oifname \"chain0\" counter accept\n",
                    lan.subnet
                ));
            }
            script.push_str("    }\n");
        }
        script.push_str("}\n");
        Ok(script)
    }

    pub fn clear_connection_mark(mark: u32) -> Result<()> {
        if mark == 0 {
            return Ok(());
        }
        for family in ["ipv4", "ipv6"] {
            // Update only our reserved bits; do not delete connections or their other marks.
            let out = Command::new("conntrack")
                .args(["-U", "-f", family, "--mark", &format!("0/{:#x}", mark)])
                .output()?;
            let error = String::from_utf8_lossy(&out.stderr);
            if !out.status.success() && !error.contains("0 flow entries") {
                return Err(ChainError::NetworkError(format!(
                    "conntrack mark cleanup: {}",
                    error
                )));
            }
        }
        Ok(())
    }

    pub fn snapshot() -> Result<Option<String>> {
        let output = Command::new("nft").args(["list", "tables"]).output()?;
        if !output.status.success() {
            return Err(ChainError::NetworkError(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        if String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|l| l.trim() == "table inet chainproxy")
        {
            Ok(Some(Self::list_table_rules()?))
        } else {
            Ok(None)
        }
    }

    pub fn restore(snapshot: Option<&str>) -> Result<()> {
        let mut script = String::new();
        if Self::snapshot()?.is_some() {
            script.push_str("delete table inet chainproxy\n");
        }
        if let Some(rules) = snapshot {
            script.push_str(rules);
        }
        if !script.is_empty() {
            Self::apply_ruleset(&script)?;
        }
        Ok(())
    }

    /// Check if nftables is installed and working
    pub fn probe_nftables() -> Result<String> {
        let output = Command::new("nft").arg("--version").output().map_err(|e| {
            ChainError::CommandError {
                cmd: "nft --version".to_string(),
                message: format!("nftables not found or cannot execute: {}", e),
            }
        })?;

        if !output.status.success() {
            return Err(ChainError::SystemError("nft command failed".to_string()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Check if inet chainproxy table currently exists
    pub fn table_exists() -> bool {
        let output = Command::new("nft")
            .args(["list", "table", TABLE_FAMILY, TABLE_NAME])
            .output();

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// Atomically apply nftables ruleset without touching other tables
    pub fn apply_ruleset(ruleset: &str) -> Result<()> {
        info!(
            "Applying nftables ruleset for table {} {}",
            TABLE_FAMILY, TABLE_NAME
        );
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ChainError::CommandError {
                cmd: "nft -f -".to_string(),
                message: format!("Failed to spawn nft process: {}", e),
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(ruleset.as_bytes())
                .map_err(|e| ChainError::CommandError {
                    cmd: "nft write stdin".to_string(),
                    message: format!("Failed to write rules to nft stdin: {}", e),
                })?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| ChainError::CommandError {
                cmd: "nft wait".to_string(),
                message: format!("Failed waiting for nft process: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ChainError::CommandError {
                cmd: "nft -f -".to_string(),
                message: format!("nftables apply failed: {}", stderr),
            });
        }

        Ok(())
    }

    /// Delete table inet chainproxy (cleans up all rules and chains we created)
    pub fn delete_table() {
        if Self::table_exists() {
            info!("Deleting nftables table {} {}", TABLE_FAMILY, TABLE_NAME);
            let output = Command::new("nft")
                .args(["delete", "table", TABLE_FAMILY, TABLE_NAME])
                .output();

            if let Ok(out) = output {
                if !out.status.success() {
                    warn!(
                        "Notice deleting table: {}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            }
        }
    }

    /// List active rules in inet chainproxy
    pub fn list_table_rules() -> Result<String> {
        let output = Command::new("nft")
            .args(["list", "table", TABLE_FAMILY, TABLE_NAME])
            .output()
            .map_err(|e| ChainError::CommandError {
                cmd: format!("nft list table {} {}", TABLE_FAMILY, TABLE_NAME),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(ChainError::NetworkError(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}
