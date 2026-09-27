use crate::error::{ChainError, Result};
use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{info, warn};

pub const TABLE_NAME: &str = "chainproxy";
pub const TABLE_FAMILY: &str = "inet";
pub const RULE_COMMENT: &str = "chainproxy-managed";

pub struct NftablesManager;

impl NftablesManager {
    /// Generate nftables ruleset string for inet chainproxy
    pub fn generate_ruleset(
        uplink: &str,
        mark_hex: &str,
        forwarded_subnets: &[String],
        enable_forward: bool,
    ) -> String {
        let mut script = String::new();
        script.push_str(&format!("add table {} {}\n", TABLE_FAMILY, TABLE_NAME));
        script.push_str(&format!("flush table {} {}\n", TABLE_FAMILY, TABLE_NAME));
        script.push_str(&format!("table {} {} {{\n", TABLE_FAMILY, TABLE_NAME));

        // 1. Prerouting hook at priority mangle (-150)
        script.push_str("    chain prerouting {\n");
        script.push_str("        type filter hook prerouting priority mangle; policy accept;\n");
        script.push_str(&format!(
            "        iifname \"{}\" ct state new ct mark set {} comment \"{}\"\n",
            uplink, mark_hex, RULE_COMMENT
        ));
        script.push_str(&format!(
            "        ct mark {} meta mark set {} comment \"{}\"\n",
            mark_hex, mark_hex, RULE_COMMENT
        ));
        script.push_str("    }\n");

        // 2. Output hook at priority mangle (-150)
        script.push_str("    chain output {\n");
        script.push_str("        type filter hook output priority mangle; policy accept;\n");
        script.push_str(&format!(
            "        ct mark {} meta mark set {} comment \"{}\"\n",
            mark_hex, mark_hex, RULE_COMMENT
        ));
        script.push_str("    }\n");

        // 3. Forward hook (for NAT VPS / Container forwarded subnets)
        if enable_forward && !forwarded_subnets.is_empty() {
            script.push_str("    chain forward {\n");
            script.push_str("        type filter hook forward priority filter; policy accept;\n");
            script.push_str(&format!(
                "        ct state established,related accept comment \"{}\"\n",
                RULE_COMMENT
            ));
            for subnet in forwarded_subnets {
                script.push_str(&format!(
                    "        ip saddr {} oifname \"chain0\" accept comment \"{}\"\n",
                    subnet, RULE_COMMENT
                ));
            }
            script.push_str("    }\n");

            // 4. Postrouting hook for Masquerade on chain0
            script.push_str("    chain postrouting {\n");
            script.push_str("        type nat hook postrouting priority srcnat; policy accept;\n");
            script.push_str(&format!(
                "        oifname \"chain0\" masquerade comment \"{}\"\n",
                RULE_COMMENT
            ));
            script.push_str("    }\n");
        }

        script.push_str("}\n");
        script
    }

    /// Check if nftables is installed and working
    pub fn probe_nftables() -> Result<String> {
        let output = Command::new("nft")
            .arg("--version")
            .output()
            .map_err(|e| ChainError::CommandError {
                cmd: "nft --version".to_string(),
                message: format!("nftables not found or cannot execute: {}", e),
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
        info!("Applying nftables ruleset for table {} {}", TABLE_FAMILY, TABLE_NAME);
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

        let output = child.wait_with_output().map_err(|e| ChainError::CommandError {
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
                    warn!("Notice deleting table: {}", String::from_utf8_lossy(&out.stderr));
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
            return Ok("Table does not exist".to_string());
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ruleset_generation() {
        let subnets = vec!["10.0.0.0/24".to_string()];
        let script = NftablesManager::generate_ruleset("eth0", "0x88", &subnets, true);

        assert!(script.contains("add table inet chainproxy"));
        assert!(script.contains("flush table inet chainproxy"));
        assert!(script.contains("iifname \"eth0\" ct state new ct mark set 0x88"));
        assert!(script.contains("ct mark 0x88 meta mark set 0x88"));
        assert!(script.contains("chain forward"));
        assert!(script.contains("ip saddr 10.0.0.0/24 oifname \"chain0\" accept"));
        assert!(script.contains("oifname \"chain0\" masquerade"));
        assert!(script.contains("chainproxy-managed"));
    }
}
