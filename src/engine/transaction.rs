use crate::engine::history::HistoryManager;
use crate::error::{ChainError, Result};
use crate::health::checker::HealthChecker;
use crate::model::config::{ChainProxyConfig, ProxyMode};
use crate::model::state::{ChainStatus, FinalHopStatus, ServiceState, TestReport, VpnHopStatus};
use crate::network::iproute::{IpRouteManager, RoutePlan};
use crate::network::nftables::NftablesManager;
use crate::network::sysctl::{SysctlManager, SysctlSnapshot};
use crate::singbox::generator::generate_singbox_config;
use crate::singbox::process::SingBoxManager;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub plan: RoutePlan,
    pub nft: Option<String>,
    pub sysctl: SysctlSnapshot,
    pub inbound_mark: u32,
    pub original_rules: Vec<serde_json::Value>,
    pub original_routes: Vec<serde_json::Value>,
}

impl NetworkSnapshot {
    pub fn capture(plan: RoutePlan, config: &ChainProxyConfig) -> Result<Self> {
        IpRouteManager::check_available(&plan)?;
        let inbound_mark = if config.routing.preserve_inbound_connections {
            config.routing.inbound_mark()?
        } else {
            0
        };
        if inbound_mark != 0 {
            let probe = std::process::Command::new("conntrack").arg("-C").output()?;
            if !probe.status.success() {
                return Err(ChainError::NetworkError(
                    String::from_utf8_lossy(&probe.stderr).into_owned(),
                ));
            }
        }
        let mut original_rules = Vec::new();
        let mut original_routes = Vec::new();
        for family in ["-4", "-6"] {
            original_rules.push(serde_json::from_str(&IpRouteManager::run(&[
                family, "-N", "-j", "rule", "show",
            ])?)?);
            let routes: Vec<serde_json::Value> = serde_json::from_str(&IpRouteManager::run(&[
                family, "-N", "-j", "route", "show", "table", "all",
            ])?)?;
            original_routes.push(serde_json::json!(routes
                .into_iter()
                .filter(|r| ["2022", "2023"]
                    .iter()
                    .any(|t| r["table"].as_str() == Some(t)))
                .collect::<Vec<_>>()));
        }
        Ok(Self {
            plan,
            nft: NftablesManager::snapshot()?,
            sysctl: SysctlManager::snapshot()?,
            inbound_mark,
            original_rules,
            original_routes,
        })
    }

    pub fn restore(&self) -> Result<()> {
        let routes = IpRouteManager::remove_plan(&self.plan);
        let nft = NftablesManager::restore(self.nft.as_deref());
        let sysctl = SysctlManager::restore(&self.sysctl);
        let marks = NftablesManager::clear_connection_mark(self.inbound_mark);
        routes.and(nft).and(sysctl).and(marks)
    }
}

pub struct ChainEngine {
    base_dir: PathBuf,
    singbox_bin: String,
    history: Arc<Mutex<HistoryManager>>,
    singbox: Arc<Mutex<SingBoxManager>>,
    network_snapshot: Option<NetworkSnapshot>,
    active_config: Arc<Mutex<Option<ChainProxyConfig>>>,
    state: Arc<Mutex<ServiceState>>,
    start_time: Option<Instant>,
    active_version: Arc<Mutex<Option<String>>>,
    watchdog_timeout_secs: AtomicU64,
}

impl ChainEngine {
    pub fn new<P: AsRef<Path>>(base_dir: P, singbox_bin: &str) -> Self {
        let base_path = base_dir.as_ref().to_path_buf();
        let history = Arc::new(Mutex::new(HistoryManager::new(&base_path)));
        let singbox = Arc::new(Mutex::new(SingBoxManager::new()));

        let cfg_file = base_path.join("config.json");
        let initial_config = if cfg_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&cfg_file) {
                serde_json::from_str::<ChainProxyConfig>(&content).ok()
            } else {
                None
            }
        } else {
            None
        };

        Self {
            base_dir: base_path,
            singbox_bin: singbox_bin.to_string(),
            history,
            singbox,
            network_snapshot: None,
            active_config: Arc::new(Mutex::new(initial_config)),
            state: Arc::new(Mutex::new(ServiceState::Stopped)),
            start_time: None,
            active_version: Arc::new(Mutex::new(None)),
            watchdog_timeout_secs: AtomicU64::new(30),
        }
    }

    pub fn set_watchdog_timeout(&self, secs: u64) {
        self.watchdog_timeout_secs.store(secs, Ordering::SeqCst);
    }

    /// Validate before touching the running configuration. All mutations share one rollback path.
    pub async fn apply(&mut self, config: ChainProxyConfig) -> Result<TestReport> {
        let parsed = config.parse_and_validate()?;
        let uplink = match &config.uplink_interface {
            Some(iface) => iface.clone(),
            None => IpRouteManager::detect_default_uplink()?.interface,
        };
        let local_ip = IpRouteManager::get_interface_ipv4(&uplink)?.to_string();
        let lans = IpRouteManager::lan_subnets(&config, &uplink)?;
        let plan = IpRouteManager::route_plan(
            &config,
            &lans,
            &IpRouteManager::detect_current_ssh_client_ips(),
        )?;
        let singbox_cfg = generate_singbox_config(&config, &parsed, &uplink, Some(&local_ip))?;
        let nft_rules = NftablesManager::generate_ruleset(&config, &lans)?;
        let resolved_sb = SingBoxManager::resolve_binary(&self.singbox_bin)?;
        let temp_dir = tempfile::tempdir()?;
        let temp_cfg_path = temp_dir.path().join("singbox_check.json");
        std::fs::write(&temp_cfg_path, serde_json::to_vec_pretty(&singbox_cfg)?)?;
        SingBoxManager::check_config(&resolved_sb, &temp_cfg_path)?;

        let previous = if *self.state.lock().unwrap() == ServiceState::Running {
            self.active_config.lock().unwrap().clone()
        } else {
            None
        };
        self.stop()?;
        *self.state.lock().unwrap() = ServiceState::Starting;
        let timeout = Duration::from_secs(self.watchdog_timeout_secs.load(Ordering::SeqCst));
        let result = tokio::time::timeout(timeout, async {
            IpRouteManager::check_available(&plan)?;
            if IpRouteManager::run(&["link", "show", "dev", "chain0"]).is_ok() {
                return Err(ChainError::NetworkError(
                    "chain0 already exists; refusing to take over another TUN".to_string(),
                ));
            }
            let snapshot = NetworkSnapshot::capture(plan, &config)?;
            std::fs::create_dir_all(&self.base_dir)?;
            let journal = self.base_dir.join("network_snapshot.json");
            let mut file = tempfile::NamedTempFile::new_in(&self.base_dir)?;
            file.write_all(&serde_json::to_vec_pretty(&snapshot)?)?;
            file.as_file().sync_all()?;
            file.persist(&journal).map_err(|e| e.error)?;
            self.network_snapshot = Some(snapshot);

            let actual_cfg_path = self.base_dir.join("singbox_active.json");
            std::fs::write(&actual_cfg_path, serde_json::to_vec_pretty(&singbox_cfg)?)?;
            let mut interfaces = vec![uplink.clone()];
            for lan in &lans {
                if !interfaces.contains(&lan.interface) {
                    interfaces.push(lan.interface.clone());
                }
            }
            SysctlManager::configure_for_proxy(
                &interfaces,
                config.is_forwarding_enabled() && !lans.is_empty(),
                config.routing.ipv6,
            )?;
            IpRouteManager::install_rules(&self.network_snapshot.as_ref().unwrap().plan)?;
            IpRouteManager::ensure_tun_device()?;
            self.singbox
                .lock()
                .unwrap()
                .start(&resolved_sb, &actual_cfg_path)?;
            if !IpRouteManager::wait_for_interface("chain0", Duration::from_secs(5)) {
                return Err(ChainError::NetworkError(
                    "chain0 did not appear within 5 seconds".to_string(),
                ));
            }
            SysctlManager::configure_tun_sysctl("chain0")?;
            IpRouteManager::install_routes(&self.network_snapshot.as_ref().unwrap().plan)?;
            // Enable marking only after the routes and physical bypass are usable.
            NftablesManager::apply_ruleset(&nft_rules)?;
            tokio::time::sleep(Duration::from_secs(3)).await;

            let (v1_name, v1_ep) = match config.mode {
                ProxyMode::SocksChainWarp | ProxyMode::StandaloneSocks => (
                    parsed
                        .socks5
                        .as_ref()
                        .map(|s| s.redacted_string())
                        .unwrap_or_default(),
                    parsed
                        .socks5
                        .as_ref()
                        .map(|s| format!("{}:{}", s.server, s.port))
                        .unwrap_or_default(),
                ),
                _ => (
                    config.vpn1.name.clone(),
                    parsed
                        .vpn1
                        .as_ref()
                        .and_then(|p| p.peers.first())
                        .and_then(|p| p.endpoint.as_ref())
                        .map(|e| e.to_string())
                        .unwrap_or_default(),
                ),
            };
            let v2_ep = parsed
                .vpn2
                .as_ref()
                .and_then(|p| p.peers.first())
                .and_then(|p| p.endpoint.as_ref())
                .map(|e| e.to_string())
                .unwrap_or_default();
            let report = HealthChecker::run_full_test(
                config.mode,
                Some(&uplink),
                &v1_name,
                &v1_ep,
                &config.vpn2.name,
                &v2_ep,
            )
            .await;
            if !report.success || !self.singbox.lock().unwrap().is_running() {
                return Err(ChainError::TransactionError {
                    stage: "TEST".to_string(),
                    message: "Proxy health check failed".to_string(),
                });
            }
            let version = self
                .history
                .lock()
                .unwrap()
                .commit_version(config.clone())?;
            *self.active_config.lock().unwrap() = Some(config);
            *self.active_version.lock().unwrap() = Some(version);
            *self.state.lock().unwrap() = ServiceState::Running;
            self.start_time = Some(Instant::now());
            Ok(report)
        })
        .await
        .unwrap_or_else(|_| {
            Err(ChainError::TransactionError {
                stage: "WATCHDOG".to_string(),
                message: "Apply timed out; restoring previous network".to_string(),
            })
        });

        if let Err(error) = result {
            *self.state.lock().unwrap() = ServiceState::RollingBack;
            self.stop()?;
            *self.state.lock().unwrap() = ServiceState::Failed;
            if let Some(previous) = previous {
                // The old network is regenerated from its committed configuration after restoring the baseline.
                if let Err(restore_error) = Box::pin(self.apply(previous)).await {
                    return Err(ChainError::TransactionError {
                        stage: "ROLLBACK".to_string(),
                        message: format!(
                            "{}; previous configuration also failed: {}",
                            error, restore_error
                        ),
                    });
                }
            }
            return Err(error);
        }
        result
    }

    pub async fn rollback(&mut self) -> Result<()> {
        let target_cfg = self.history.lock().unwrap().get_rollback_target()?;
        self.apply(target_cfg).await.map(|_| ())
    }

    pub fn stop(&mut self) -> Result<()> {
        let journal = self.base_dir.join("network_snapshot.json");
        if self.network_snapshot.is_none() && journal.exists() {
            self.network_snapshot = Some(serde_json::from_slice(&std::fs::read(&journal)?)?);
        }
        if let Some(snapshot) = &self.network_snapshot {
            // Remove selection before the TUN goes away. Never flush main or another firewall table.
            let nft = NftablesManager::restore(None);
            self.singbox.lock().unwrap().stop();
            let restored = snapshot.restore();
            nft.and(restored)?;
            if journal.exists() {
                std::fs::remove_file(&journal)?;
            }
            self.network_snapshot = None;
        } else {
            self.singbox.lock().unwrap().stop();
        }
        *self.state.lock().unwrap() = ServiceState::Stopped;
        self.start_time = None;
        *self.active_version.lock().unwrap() = None;
        info!("Original network state restored");
        Ok(())
    }

    /// Query current status
    pub fn get_status(&self) -> ChainStatus {
        let state = self.state.lock().unwrap().clone();
        let uptime = self.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0);
        let active_ver = self.active_version.lock().unwrap().clone();

        let cfg_opt = {
            let in_memory = self.active_config.lock().unwrap().clone();
            if in_memory.is_some() && state == ServiceState::Running {
                in_memory
            } else {
                let cfg_path = self.base_dir.join("config.json");
                if cfg_path.exists() {
                    if let Ok(c) = std::fs::read_to_string(&cfg_path) {
                        serde_json::from_str::<ChainProxyConfig>(&c)
                            .ok()
                            .or(in_memory)
                    } else {
                        in_memory
                    }
                } else {
                    in_memory
                }
            }
        };

        let uplink = cfg_opt.as_ref().and_then(|c| c.uplink_interface.as_deref());
        let phys = HealthChecker::probe_physical(uplink);

        let (vpn1_hop, vpn2_hop, final_hop) = if let Some(ref cfg) = cfg_opt {
            let v1_configured = match cfg.mode {
                ProxyMode::SocksChainWarp | ProxyMode::StandaloneSocks => cfg.socks5.is_some(),
                _ => !cfg.vpn1.wireguard_config.trim().is_empty(),
            };

            let v2_configured = match cfg.mode {
                ProxyMode::StandaloneWg | ProxyMode::StandaloneSocks => false,
                _ => !cfg.vpn2.wireguard_config.trim().is_empty(),
            };

            let (v1_name, v1_ep) = match cfg.mode {
                ProxyMode::SocksChainWarp | ProxyMode::StandaloneSocks => {
                    let s_str = cfg
                        .socks5
                        .as_ref()
                        .map(|s| s.redacted_string())
                        .unwrap_or_else(|| "Socks5 节点".to_string());
                    let s_ep = cfg
                        .socks5
                        .as_ref()
                        .map(|s| format!("{}:{}", s.server, s.port))
                        .unwrap_or_default();
                    (s_str, s_ep)
                }
                _ => (
                    if cfg.vpn1.name.is_empty() {
                        "WireGuard 节点".to_string()
                    } else {
                        cfg.vpn1.name.clone()
                    },
                    if v1_configured {
                        "已就绪".to_string()
                    } else {
                        "".to_string()
                    },
                ),
            };

            let (v2_name, v2_ep) = match cfg.mode {
                ProxyMode::StandaloneWg | ProxyMode::StandaloneSocks => {
                    ("Cloudflare WARP (未使用)".to_string(), "".to_string())
                }
                _ => (
                    if cfg.vpn2.name.is_empty() {
                        "Cloudflare WARP".to_string()
                    } else {
                        cfg.vpn2.name.clone()
                    },
                    if v2_configured {
                        "已就绪".to_string()
                    } else {
                        "".to_string()
                    },
                ),
            };

            let v1_status = if !v1_configured {
                "未配置".to_string()
            } else if state == ServiceState::Running {
                "运行中".to_string()
            } else if state == ServiceState::Failed {
                "启动失败".to_string()
            } else {
                "待启动".to_string()
            };

            let v2_status = match cfg.mode {
                ProxyMode::StandaloneWg | ProxyMode::StandaloneSocks => "未使用".to_string(),
                _ => {
                    if !v2_configured {
                        "未配置".to_string()
                    } else if state == ServiceState::Running {
                        "运行中".to_string()
                    } else if state == ServiceState::Failed {
                        "启动失败".to_string()
                    } else {
                        "待启动".to_string()
                    }
                }
            };

            (
                VpnHopStatus {
                    name: v1_name,
                    endpoint: v1_ep,
                    config_valid: v1_configured,
                    reachable: state == ServiceState::Running && v1_configured,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: v1_status,
                    message: None,
                },
                VpnHopStatus {
                    name: v2_name,
                    endpoint: v2_ep,
                    config_valid: v2_configured,
                    reachable: state == ServiceState::Running && v2_configured,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: v2_status,
                    message: None,
                },
                FinalHopStatus {
                    internet_ok: state == ServiceState::Running,
                    exit_ip: None,
                    exit_country: None,
                    exit_isp: None,
                    latency_ms: None,
                    status: if state == ServiceState::Running {
                        "正常".to_string()
                    } else {
                        "离线".to_string()
                    },
                },
            )
        } else {
            (
                VpnHopStatus {
                    name: "WireGuard / 入口节点".to_string(),
                    endpoint: "".to_string(),
                    config_valid: false,
                    reachable: false,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: "未配置".to_string(),
                    message: None,
                },
                VpnHopStatus {
                    name: "Cloudflare WARP".to_string(),
                    endpoint: "".to_string(),
                    config_valid: false,
                    reachable: false,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: "未配置".to_string(),
                    message: None,
                },
                FinalHopStatus {
                    internet_ok: false,
                    exit_ip: None,
                    exit_country: None,
                    exit_isp: None,
                    latency_ms: None,
                    status: "离线".to_string(),
                },
            )
        };

        let chain_visual = if let Some(ref cfg) = cfg_opt {
            let internet_status = if final_hop.internet_ok {
                "正常 (OK)"
            } else {
                "离线 (OFF)"
            };
            match cfg.mode {
                ProxyMode::WgChainWarp => format!(
                    "VPS [{}] -> WireGuard [{}] -> WARP [{}] -> 目标公网 [{}]",
                    phys.status, vpn1_hop.status, vpn2_hop.status, internet_status
                ),
                ProxyMode::SocksChainWarp => format!(
                    "VPS [{}] -> Socks5 [{}] -> WARP [{}] -> 目标公网 [{}]",
                    phys.status, vpn1_hop.status, vpn2_hop.status, internet_status
                ),
                ProxyMode::StandaloneWg => format!(
                    "VPS [{}] -> WireGuard [{}] -> 目标公网 [{}]",
                    phys.status, vpn1_hop.status, internet_status
                ),
                ProxyMode::StandaloneSocks => format!(
                    "VPS [{}] -> Socks5 [{}] -> 目标公网 [{}]",
                    phys.status, vpn1_hop.status, internet_status
                ),
                ProxyMode::StandaloneWarp => format!(
                    "VPS [{}] -> WARP [{}] -> 目标公网 [{}]",
                    phys.status, vpn2_hop.status, internet_status
                ),
            }
        } else {
            format!(
                "VPS [{}] -> 入口 [未配置] -> 出口 [未配置] -> 目标公网 [离线 (OFF)]",
                phys.status
            )
        };

        ChainStatus {
            state,
            active_config_version: active_ver,
            uptime_seconds: uptime,
            physical: phys,
            vpn1: vpn1_hop,
            vpn2: vpn2_hop,
            final_hop,
            chain_visual,
        }
    }

    pub fn get_active_config(&self) -> Option<ChainProxyConfig> {
        self.active_config.lock().unwrap().clone()
    }
}
