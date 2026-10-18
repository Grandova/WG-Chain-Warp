use crate::error::{ChainError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::info;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SysctlSnapshot {
    pub values: BTreeMap<String, String>,
}

pub struct SysctlManager;

impl SysctlManager {
    /// Fast direct read from /proc/sys/<key>, falling back to sysctl binary only if needed
    pub fn get(key: &str) -> Option<String> {
        let proc_path = format!("/proc/sys/{}", key.replace('.', "/"));
        if let Ok(val) = fs::read_to_string(&proc_path) {
            return Some(val.trim().to_string());
        }
        let output = Command::new("sysctl").args(["-n", key]).output().ok()?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        }
    }

    /// Fast direct write to /proc/sys/<key>, skipping subprocess spawn when value is already set
    pub fn set(key: &str, value: &str) -> Result<()> {
        let proc_path = format!("/proc/sys/{}", key.replace('.', "/"));
        if let Ok(current) = fs::read_to_string(&proc_path) {
            if current.trim() == value {
                return Ok(());
            }
        }
        if Path::new(&proc_path).exists() && fs::write(&proc_path, format!("{}\n", value)).is_ok() {
            return Ok(());
        }

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

    /// Snapshot only the sysctl keys that Sooya may modify
    pub fn snapshot() -> Result<SysctlSnapshot> {
        let mut values = BTreeMap::new();
        if let Ok(entries) = fs::read_dir("/proc/sys/net/ipv4/conf") {
            for entry in entries.flatten() {
                let dir = entry.path();
                for subkey in ["rp_filter", "send_redirects"] {
                    let path = dir.join(subkey);
                    if let Ok(val) = fs::read_to_string(&path) {
                        if let Ok(rel) = path.strip_prefix("/proc/sys/") {
                            values.insert(
                                rel.to_string_lossy().into_owned(),
                                val.trim().to_string(),
                            );
                        }
                    }
                }
            }
        }
        Ok(SysctlSnapshot { values })
    }

    pub fn configure_for_proxy(interfaces: &[String], _forward: bool, _ipv6: bool) -> Result<()> {
        for iface in ["all", "default"]
            .into_iter()
            .chain(interfaces.iter().map(String::as_str))
        {
            Self::set(&format!("net/ipv4/conf/{}/rp_filter", iface), "0")?;
            Self::set(&format!("net/ipv4/conf/{}/send_redirects", iface), "0")?;
        }
        Ok(())
    }

    pub fn configure_tun_sysctl(tun_name: &str) -> Result<()> {
        Self::set(&format!("net/ipv4/conf/{}/rp_filter", tun_name), "0")?;
        Self::set(&format!("net/ipv4/conf/{}/send_redirects", tun_name), "0")?;
        Ok(())
    }

    pub fn restore(snapshot: &SysctlSnapshot) -> Result<()> {
        info!("Restoring sysctl values from snapshot");
        let mut error = None;
        for (key, val) in &snapshot.values {
            if let Some(current) = Self::get(key) {
                if current != *val {
                    if let Err(e) = Self::set(key, val) {
                        error = Some(e);
                    }
                }
            }
        }
        match error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
