use crate::error::{ChainError, Result};
use std::collections::HashMap;
use std::process::Command;
use tracing::{info, warn};

pub struct SysctlSnapshot {
    pub values: HashMap<String, String>,
}

pub struct SysctlManager;

impl SysctlManager {
    /// Read sysctl key value
    pub fn get(key: &str) -> Option<String> {
        let output = Command::new("sysctl").args(["-n", key]).output().ok()?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        }
    }

    /// Set sysctl key value
    pub fn set(key: &str, value: &str) -> Result<()> {
        let pair = format!("{}={}", key, value);
        let output = Command::new("sysctl")
            .args(["-w", &pair])
            .output()
            .map_err(|e| ChainError::CommandError {
                cmd: format!("sysctl -w {}", pair),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(ChainError::NetworkError(format!(
                "Failed to set sysctl {}: {}",
                pair,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Snapshot and apply required sysctl settings for forwarding and loose rp_filter
    pub fn configure_for_proxy(uplink: &str) -> SysctlSnapshot {
        let mut snapshot = HashMap::new();
        let keys = vec![
            "net.ipv4.ip_forward".to_string(),
            "net.ipv4.conf.all.rp_filter".to_string(),
            format!("net.ipv4.conf.{}.rp_filter", uplink),
        ];

        for key in &keys {
            if let Some(val) = Self::get(key) {
                snapshot.insert(key.clone(), val);
            }
        }

        // Apply optimized values
        info!("Configuring sysctl parameters for chainproxy");
        let _ = Self::set("net.ipv4.ip_forward", "1");
        let _ = Self::set("net.ipv4.conf.all.rp_filter", "2");
        let _ = Self::set(&format!("net.ipv4.conf.{}.rp_filter", uplink), "2");

        SysctlSnapshot { values: snapshot }
    }

    /// Restore sysctl snapshot values
    pub fn restore(snapshot: &SysctlSnapshot) {
        info!("Restoring sysctl values from snapshot");
        for (key, val) in &snapshot.values {
            if let Err(e) = Self::set(key, val) {
                warn!("Could not restore sysctl {}={}: {}", key, val, e);
            }
        }
    }
}
