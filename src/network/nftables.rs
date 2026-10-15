use crate::error::{ChainError, Result};
use std::io::Write;
use std::process::{Command, Stdio};
use tracing::info;

pub const TABLE_NAME: &str = "chainproxy";
pub const TABLE_FAMILY: &str = "inet";

pub struct NftablesManager;

impl NftablesManager {
    pub fn generate_ruleset(config: &crate::model::config::ChainProxyConfig) -> Result<String> {
        use crate::network::iproute::{MARK_HOST_PROXY, MARK_MASK, MARK_PHYSICAL_DIRECT};
        let inbound = config.routing.inbound_mark()?;
        let mask = MARK_MASK | inbound;
        let keep = !mask;
        let mut script =
            "add table inet chainproxy\nflush table inet chainproxy\ntable inet chainproxy {\n"
                .to_string();
        script.push_str(
            "    chain prerouting {\n        type filter hook prerouting priority mangle; policy accept;\n",
        );
        script.push_str(
            "        iifname \"chain0\" fib daddr type != local drop comment \"prevent-tun-loop\"\n",
        );
        script.push_str(&format!(
            "        iifname != \"chain0\" iifname != \"lo\" ct direction original ct mark & {mask:#x} == 0 ct mark set ct mark | {inbound:#x} comment \"inbound-return\"\n"
        ));
        script.push_str("    }\n    chain output {\n        type route hook output priority mangle; policy accept;\n");
        script.push_str(&format!("        meta mark & {MARK_PHYSICAL_DIRECT:#x} != 0 return\n"));
        script.push_str(&format!(
            "        ct direction reply meta mark set (meta mark & {keep:#x}) | {inbound:#x} return comment \"inbound-reply-direct\"\n"
        ));
        script.push_str(&format!(
            "        ct mark & {inbound:#x} == {inbound:#x} meta mark set (meta mark & {keep:#x}) | {inbound:#x} return comment \"inbound-mark-direct\"\n"
        ));
        script.push_str("        fib daddr type local return\n");
        if config.routing.proxy_host_outbound {
            if !config.routing.ipv6 {
                script.push_str("        meta nfproto ipv6 udp dport 53 drop comment \"block-ipv6-dns-leak\"\n");
                script.push_str("        meta nfproto ipv6 tcp dport 53 drop comment \"block-ipv6-dns-leak\"\n");
            }
            let family = if config.routing.ipv6 { "" } else { "meta nfproto ipv4 " };
            script.push_str(&format!(
                "        {family}udp dport 53 meta mark set (meta mark & {keep:#x}) | {MARK_HOST_PROXY:#x} accept comment \"dns-udp-outbound\"\n"
            ));
            script.push_str(&format!(
                "        {family}tcp dport 53 meta mark set (meta mark & {keep:#x}) | {MARK_HOST_PROXY:#x} accept comment \"dns-tcp-outbound\"\n"
            ));
            script.push_str(
                "        ip daddr { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32 } return comment \"lan-bypass-v4\"\n",
            );
            if config.routing.ipv6 {
                script.push_str(
                    "        ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return comment \"lan-bypass-v6\"\n",
                );
            }
            script.push_str(&format!(
                "        {family}ct direction original meta mark & {mask:#x} == 0 meta mark set (meta mark & {keep:#x}) | {MARK_HOST_PROXY:#x} comment \"host-proxy\"\n"
            ));
        }
        script.push_str("    }\n    chain postrouting {\n        type filter hook postrouting priority mangle; policy accept;\n        oifname \"chain0\" tcp flags syn / syn,rst tcp option maxseg size set 1200 comment \"mss-clamp\"\n    }\n}\n");
        Ok(script)
    }

    pub fn clear_connection_mark(mark: u32) -> Result<()> {
        if mark != 0 {
            for family in ["ipv4", "ipv6"] {
                let _ = Command::new("conntrack")
                    .args(["-U", "-f", family, "--mark", &format!("0/{:#x}", mark)])
                    .output();
            }
        }
        Ok(())
    }

    pub fn snapshot() -> Result<Option<String>> {
        let output = Command::new("nft").args(["list", "tables"]).output()?;
        if !output.status.success() {
            return Err(ChainError::NetworkError(String::from_utf8_lossy(&output.stderr).into_owned()));
        }
        if String::from_utf8_lossy(&output.stdout).lines().any(|l| l.trim() == "table inet chainproxy") {
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

    pub fn apply_ruleset(ruleset: &str) -> Result<()> {
        info!("Applying nftables ruleset for table {} {}", TABLE_FAMILY, TABLE_NAME);
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ChainError::CommandError {
                cmd: "nft -f -".to_string(),
                message: format!("Failed to spawn nft process: {}", e),
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ruleset.as_bytes()).map_err(|e| ChainError::CommandError {
                cmd: "nft write stdin".to_string(),
                message: format!("Failed to write rules to nft stdin: {}", e),
            })?;
        }

        let output = child.wait_with_output().map_err(|e| ChainError::CommandError {
            cmd: "nft wait".to_string(),
            message: format!("Failed waiting for nft process: {}", e),
        })?;

        if !output.status.success() {
            return Err(ChainError::CommandError {
                cmd: "nft -f -".to_string(),
                message: format!("nftables apply failed: {}", String::from_utf8_lossy(&output.stderr)),
            });
        }
        Ok(())
    }

    pub fn list_table_rules() -> Result<String> {
        let output = Command::new("nft")
            .args(["list", "table", TABLE_FAMILY, TABLE_NAME])
            .output()
            .map_err(|e| ChainError::CommandError {
                cmd: format!("nft list table {} {}", TABLE_FAMILY, TABLE_NAME),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(ChainError::NetworkError(String::from_utf8_lossy(&output.stderr).into_owned()));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::config::ChainProxyConfig;

    #[test]
    fn ruleset_bypasses_all_inbound_replies_and_only_proxies_outbound_original() {
        let mut cfg = ChainProxyConfig::default();
        cfg.routing.preserve_inbound_connections = false;
        let ruleset = NftablesManager::generate_ruleset(&cfg).unwrap();
        assert!(ruleset.contains("ct direction reply meta mark set"));
        assert!(ruleset.contains("ct mark & 0x88 == 0x88 meta mark set"));
        assert!(ruleset.contains("ct direction original meta mark & 0xc88 == 0 meta mark set"));
    }
}

