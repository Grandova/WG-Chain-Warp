use crate::error::{ChainError, Result};
use crate::model::config::ChainProxyConfig;
use chrono::Utc;
use std::collections::VecDeque;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::info;

pub const MAX_HISTORY_VERSIONS: usize = 10;

#[derive(Debug, Clone)]
pub struct ConfigVersion {
    pub version_id: String,
    pub timestamp: String,
    pub config: ChainProxyConfig,
}

pub struct HistoryManager {
    base_dir: PathBuf,
    history: VecDeque<ConfigVersion>,
    last_known_good: Option<ConfigVersion>,
}

impl HistoryManager {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        let base_path = base_dir.as_ref().to_path_buf();
        let mut mgr = Self {
            base_dir: base_path,
            history: VecDeque::with_capacity(MAX_HISTORY_VERSIONS + 1),
            last_known_good: None,
        };
        let _ = mgr.load_from_disk();
        mgr
    }

    fn versions_dir(&self) -> PathBuf {
        self.base_dir.join("versions")
    }

    fn last_known_good_path(&self) -> PathBuf {
        self.base_dir.join("last_known_good.json")
    }

    pub fn load_from_disk(&mut self) -> Result<()> {
        let lkg_path = self.last_known_good_path();
        if lkg_path.exists() {
            if let Ok(mut f) = File::open(&lkg_path) {
                let mut content = String::new();
                if f.read_to_string(&mut content).is_ok() {
                    if let Ok(cfg) = serde_json::from_str::<ChainProxyConfig>(&content) {
                        self.last_known_good = Some(ConfigVersion {
                            version_id: "initial_lkg".to_string(),
                            timestamp: Utc::now().to_rfc3339(),
                            config: cfg,
                        });
                        info!("Loaded last_known_good configuration from {:?}", lkg_path);
                    }
                }
            }
        }
        Ok(())
    }

    /// Save a newly committed version into history and set as last_known_good
    pub fn commit_version(&mut self, config: ChainProxyConfig) -> Result<String> {
        let version_id = Utc::now().format("%Y%m%d_%H%M%S_%f").to_string();
        let timestamp = Utc::now().to_rfc3339();

        let version = ConfigVersion {
            version_id: version_id.clone(),
            timestamp,
            config: config.clone(),
        };

        let v_dir = self.versions_dir();
        create_dir_all(&v_dir)?;
        let contents = serde_json::to_vec_pretty(&config)?;
        let mut version_file = File::create(v_dir.join(format!("{}.json", version_id)))?;
        version_file.write_all(&contents)?;
        version_file.sync_all()?;
        let mut pending = tempfile::NamedTempFile::new_in(&self.base_dir)?;
        pending.write_all(&contents)?;
        pending.as_file().sync_all()?;
        pending
            .persist(self.last_known_good_path())
            .map_err(|e| e.error)?;

        self.last_known_good = Some(version.clone());
        self.history.push_back(version);

        while self.history.len() > MAX_HISTORY_VERSIONS {
            self.history.pop_front();
        }

        info!("Committed configuration version '{}'", version_id);
        Ok(version_id)
    }

    /// Retrieve last known good configuration
    pub fn get_last_known_good(&self) -> Option<ChainProxyConfig> {
        self.last_known_good.as_ref().map(|v| v.config.clone())
    }

    /// Pop previous version for rollback
    pub fn get_rollback_target(&mut self) -> Result<ChainProxyConfig> {
        // Pop current version and return the one before it
        if self.history.len() >= 2 {
            self.history.pop_back(); // Remove current
            if let Some(prev) = self.history.back() {
                return Ok(prev.config.clone());
            }
        }

        if let Some(lkg) = &self.last_known_good {
            return Ok(lkg.config.clone());
        }

        Err(ChainError::TransactionError {
            stage: "Rollback".to_string(),
            message: "No previous configuration version available for rollback".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::config::{DnsConfig, RoutingConfig, VpnNodeConfig};

    #[test]
    fn test_history_commit_and_rollback() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut mgr = HistoryManager::new(temp_dir.path());

        let cfg1 = ChainProxyConfig {
            enabled: true,
            socks5_server: None,
            mode: Default::default(),
            uplink_interface: Some("eth0".to_string()),
            vpn1: VpnNodeConfig {
                name: "VPN1".to_string(),
                wireguard_config: "test1".to_string(),
            },
            vpn2: VpnNodeConfig {
                name: "VPN2".to_string(),
                wireguard_config: "test2".to_string(),
            },
            socks5: None,
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
            gateway: crate::model::config::GatewayConfig::default(),
            log_level: "info".to_string(),
        };

        let mut cfg2 = cfg1.clone();
        cfg2.vpn1.name = "VPN1_v2".to_string();

        mgr.commit_version(cfg1.clone()).unwrap();
        mgr.commit_version(cfg2.clone()).unwrap();

        assert_eq!(mgr.history.len(), 2);
        assert_eq!(
            mgr.last_known_good.as_ref().unwrap().config.vpn1.name,
            "VPN1_v2"
        );

        let rollback = mgr.get_rollback_target().unwrap();
        assert_eq!(rollback.vpn1.name, "VPN1");
    }
}
