use crate::error::{ChainError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::process::Command;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysctlSnapshot {
    pub values: BTreeMap<String, String>,
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

    pub fn snapshot() -> Result<SysctlSnapshot> {
        let mut values = BTreeMap::new();
        // Changing ip_forward resets per-interface IPv4 defaults. Save them before the first write.
        for entry in std::fs::read_dir("/proc/sys/net/ipv4/conf")? {
            for key in std::fs::read_dir(entry?.path())? {
                let path = key?.path();
                let name = path
                    .strip_prefix("/proc/sys/")
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                values.insert(name, std::fs::read_to_string(path)?.trim().to_string());
            }
        }
        for key in ["net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"] {
            values.insert(
                key.to_string(),
                Self::get(key).ok_or_else(|| {
                    ChainError::NetworkError(format!("Cannot read sysctl {}", key))
                })?,
            );
        }
        for entry in std::fs::read_dir("/proc/sys/net/ipv6/conf")? {
            let dir = entry?.path();
            for key in ["accept_ra", "forwarding"] {
                let path = dir.join(key);
                let name = path
                    .strip_prefix("/proc/sys/")
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                values.insert(name, std::fs::read_to_string(path)?.trim().to_string());
            }
        }
        Ok(SysctlSnapshot { values })
    }

    pub fn configure_for_proxy(interfaces: &[String], forward: bool, ipv6: bool) -> Result<()> {
        if forward && Self::get("net/ipv4/ip_forward").as_deref() != Some("1") {
            Self::set("net/ipv4/ip_forward", "1")?;
        }
        for iface in std::iter::once("all").chain(interfaces.iter().map(String::as_str)) {
            Self::set(&format!("net/ipv4/conf/{}/rp_filter", iface), "0")?;
            Self::set(&format!("net/ipv4/conf/{}/send_redirects", iface), "0")?;
        }
        if forward && ipv6 {
            for iface in interfaces {
                let key = format!("net/ipv6/conf/{}/accept_ra", iface);
                if Self::get(&key).as_deref() == Some("1") {
                    Self::set(&key, "2")?;
                }
            }
            Self::set("net/ipv6/conf/all/forwarding", "1")?;
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
        // Restore forwarding first because it resets other IPv4 settings.
        for key in ["net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"] {
            if let Some(val) = snapshot.values.get(key) {
                if Self::get(key).as_ref() != Some(val) {
                    Self::set(key, val)?;
                }
            }
        }
        let mut error = None;
        for (key, val) in &snapshot.values {
            if key == "net/ipv4/ip_forward" || key == "net/ipv6/conf/all/forwarding" {
                continue;
            }
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
