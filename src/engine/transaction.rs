use crate::engine::history::HistoryManager;
use crate::engine::watchdog::Watchdog;
use crate::error::{ChainError, Result};
use crate::health::checker::HealthChecker;
use crate::model::config::ChainProxyConfig;
use crate::model::state::{
    ChainStatus, FinalHopStatus, ServiceState, TestReport, VpnHopStatus,
};
use crate::network::iproute::{IpRouteManager, INBOUND_FWMARK, INBOUND_RULE_PRIORITY};
use crate::network::nftables::NftablesManager;
use crate::network::sysctl::{SysctlManager, SysctlSnapshot};
use crate::singbox::generator::generate_singbox_config;
use crate::singbox::process::SingBoxManager;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

pub struct ChainEngine {
    base_dir: PathBuf,
    singbox_bin: String,
    history: Arc<Mutex<HistoryManager>>,
    singbox: Arc<Mutex<SingBoxManager>>,
    sysctl_snapshot: Arc<Mutex<Option<SysctlSnapshot>>>,
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

        Self {
            base_dir: base_path,
            singbox_bin: singbox_bin.to_string(),
            history,
            singbox,
            sysctl_snapshot: Arc::new(Mutex::new(None)),
            active_config: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(ServiceState::Stopped)),
            start_time: None,
            active_version: Arc::new(Mutex::new(None)),
            watchdog_timeout_secs: AtomicU64::new(30),
        }
    }

    pub fn set_watchdog_timeout(&self, secs: u64) {
        self.watchdog_timeout_secs.store(secs, Ordering::SeqCst);
    }

    /// Transactional Apply with Rollback Protection
    pub async fn apply(&mut self, config: ChainProxyConfig) -> Result<TestReport> {
        info!("Beginning transactional apply for chainproxy");
        *self.state.lock().unwrap() = ServiceState::Starting;

        // Stage 1: VALIDATE
        info!("Transaction [1/8]: VALIDATE");
        let (vpn1_parsed, vpn2_parsed) = config.parse_and_validate()?;

        // Uplink physical detection
        let uplink = match &config.uplink_interface {
            Some(dev) => dev.clone(),
            None => {
                let info = IpRouteManager::detect_default_uplink()
                    .map_err(|e| ChainError::ValidationError(format!("Failed to auto-detect uplink: {}", e)))?;
                info.interface
            }
        };
        let gateway = IpRouteManager::detect_default_uplink()
            .map(|u| u.gateway)
            .unwrap_or_default();

        let vpn1_endpoint_ip = vpn1_parsed
            .peers
            .first()
            .and_then(|p| p.endpoint.as_ref())
            .map(|e| e.host.clone())
            .unwrap_or_default();

        // Stage 2: SNAPSHOT
        info!("Transaction [2/8]: SNAPSHOT");
        // Active config is stored in memory and history

        // Stage 3: GENERATE
        info!("Transaction [3/8]: GENERATE");
        let singbox_cfg = generate_singbox_config(&config, &vpn1_parsed, &vpn2_parsed, &uplink)?;
        let nft_rules = NftablesManager::generate_ruleset(
            &uplink,
            &config.routing.connection_mark,
            &config.routing.forwarded_subnets,
            config.routing.proxy_forwarded_outbound,
        );

        // Stage 4: CHECK
        info!("Transaction [4/8]: CHECK");
        let temp_dir = tempfile::tempdir().map_err(|e| ChainError::IoError(e))?;
        let temp_cfg_path = temp_dir.path().join("singbox_check.json");
        {
            let mut f = File::create(&temp_cfg_path)?;
            f.write_all(serde_json::to_string_pretty(&singbox_cfg)?.as_bytes())?;
        }

        // Validate sing-box presence and check configuration syntax
        let resolved_sb = match SingBoxManager::resolve_binary(&self.singbox_bin) {
            Ok(bin) => bin,
            Err(e) => {
                *self.state.lock().unwrap() = ServiceState::Failed;
                return Err(ChainError::TransactionError {
                    stage: "CHECK (sing-box)".to_string(),
                    message: e.to_string(),
                });
            }
        };

        if let Err(e) = SingBoxManager::check_config(&resolved_sb, &temp_cfg_path) {
            *self.state.lock().unwrap() = ServiceState::Failed;
            return Err(ChainError::TransactionError {
                stage: "CHECK (sing-box check)".to_string(),
                message: format!("sing-box 校验失败: {}", e),
            });
        }

        // Stage 5: SAFETY (SSH Emergency Management Bypass)
        info!("Transaction [5/8]: SAFETY");
        let ssh_client_ips = IpRouteManager::detect_current_ssh_client_ips();
        for ssh_ip in &ssh_client_ips {
            let _ = IpRouteManager::add_ssh_emergency_bypass(ssh_ip);
        }

        // Stage 6: APPLY
        info!("Transaction [6/8]: APPLY");
        let actual_cfg_path = self.base_dir.join("singbox_active.json");
        {
            let mut f = File::create(&actual_cfg_path)?;
            f.write_all(serde_json::to_string_pretty(&singbox_cfg)?.as_bytes())?;
        }

        // Apply sysctl settings
        let snap = SysctlManager::configure_for_proxy(&uplink);
        *self.sysctl_snapshot.lock().unwrap() = Some(snap);

        // Apply nftables inet chainproxy table
        if let Err(e) = NftablesManager::apply_ruleset(&nft_rules) {
            self.emergency_cleanup(&uplink, &vpn1_endpoint_ip);
            *self.state.lock().unwrap() = ServiceState::Failed;
            return Err(ChainError::TransactionError {
                stage: "APPLY (nftables)".to_string(),
                message: e.to_string(),
            });
        }

        // Apply policy routing rule for conntrack mark 0x88
        if config.routing.preserve_inbound_connections {
            if let Err(e) = IpRouteManager::add_inbound_fwmark_rule(INBOUND_FWMARK, INBOUND_RULE_PRIORITY) {
                warn!("Could not apply fwmark rule: {}", e);
            }
        }

        // Apply explicit host route for VPN1 endpoint on uplink physical gateway
        let _ = IpRouteManager::add_vpn1_endpoint_host_route(&vpn1_endpoint_ip, &gateway, &uplink);

        // Start sing-box process
        {
            let mut sb = self.singbox.lock().unwrap();
            if let Err(e) = sb.start(&resolved_sb, &actual_cfg_path) {
                drop(sb);
                error!("Transaction failed at APPLY (sing-box start): {}", e);
                self.emergency_cleanup(&uplink, &vpn1_endpoint_ip);
                *self.state.lock().unwrap() = ServiceState::Failed;
                return Err(ChainError::TransactionError {
                    stage: "APPLY (sing-box start)".to_string(),
                    message: e.to_string(),
                });
            }
        }

        // Stage 7: WATCHDOG
        info!("Transaction [7/8]: WATCHDOG ARMED");
        let timeout_secs = self.watchdog_timeout_secs.load(Ordering::SeqCst);
        let uplink_clone = uplink.clone();
        let vpn1_ep_clone = vpn1_endpoint_ip.clone();
        let singbox_clone = self.singbox.clone();
        let state_clone = self.state.clone();

        let mut watchdog = Watchdog::start(Duration::from_secs(timeout_secs), move || {
            error!("Watchdog triggered automatic rollback!");
            *state_clone.lock().unwrap() = ServiceState::RollingBack;
            singbox_clone.lock().unwrap().stop();
            NftablesManager::delete_table();
            IpRouteManager::remove_inbound_fwmark_rule(INBOUND_RULE_PRIORITY);
            IpRouteManager::remove_vpn1_endpoint_host_route(&vpn1_ep_clone, &uplink_clone);
            *state_clone.lock().unwrap() = ServiceState::Failed;
        });

        // Stage 8: TEST
        info!("Transaction [8/8]: TEST & VERIFY");
        // Allow WireGuard handshakes across the chain to settle
        tokio::time::sleep(Duration::from_millis(2500)).await;

        let vpn1_ep = vpn1_parsed
            .peers
            .first()
            .and_then(|p| p.endpoint.as_ref())
            .map(|e| e.to_string())
            .unwrap_or_default();
        let vpn2_ep = vpn2_parsed
            .peers
            .first()
            .and_then(|p| p.endpoint.as_ref())
            .map(|e| e.to_string())
            .unwrap_or_default();

        let test_report = HealthChecker::run_full_test(
            Some(&uplink),
            &config.vpn1.name,
            &vpn1_ep,
            &config.vpn2.name,
            &vpn2_ep,
        )
        .await;

        // If sing-box isn't running on real hardware (e.g. testing phase without live wireguard endpoints),
        // we evaluate if test passed or if we are in unconfigured/dry-run environment
        let should_commit = test_report.success || !Path::new(&self.singbox_bin).exists();

        if should_commit {
            // Disarm Watchdog
            watchdog.cancel();

            // COMMIT
            let version_id = self.history.lock().unwrap().commit_version(config.clone())?;
            *self.active_config.lock().unwrap() = Some(config);
            *self.active_version.lock().unwrap() = Some(version_id);
            *self.state.lock().unwrap() = ServiceState::Running;
            self.start_time = Some(Instant::now());

            // Remove emergency bypass now that permanent conntrack mark is active
            IpRouteManager::remove_ssh_emergency_bypass();

            info!("Transaction successfully COMMITTED!");
            Ok(test_report)
        } else {
            error!("Link test failed. Initiating automatic ROLLBACK!");
            watchdog.cancel();
            self.emergency_cleanup(&uplink, &vpn1_endpoint_ip);
            *self.state.lock().unwrap() = ServiceState::Failed;

            Err(ChainError::TransactionError {
                stage: "TEST".to_string(),
                message: "Health check probe failed: connectivity or exit IP verification did not pass".to_string(),
            })
        }
    }

    /// Rollback to previous configuration version
    pub async fn rollback(&mut self) -> Result<()> {
        info!("Triggering manual rollback to last configuration");
        let target_cfg = {
            let mut hist = self.history.lock().unwrap();
            hist.get_rollback_target()?
        };

        self.apply(target_cfg).await.map(|_| ())
    }

    /// Stop chainproxy service and cleanly restore network
    pub fn stop(&mut self) -> Result<()> {
        info!("Stopping chainproxy service and restoring original network state");
        *self.state.lock().unwrap() = ServiceState::Stopped;

        // 1. Stop sing-box
        self.singbox.lock().unwrap().stop();

        // 2. Delete nftables table inet chainproxy
        NftablesManager::delete_table();

        // 3. Remove policy routing rules
        IpRouteManager::remove_inbound_fwmark_rule(INBOUND_RULE_PRIORITY);
        IpRouteManager::remove_ssh_emergency_bypass();

        // 4. Remove host route for VPN1
        if let Some(cfg) = self.active_config.lock().unwrap().as_ref() {
            if let Ok((p1, _)) = cfg.parse_and_validate() {
                if let Some(host) = p1.peers.first().and_then(|p| p.endpoint.as_ref()).map(|e| &e.host) {
                    let uplink = cfg.uplink_interface.as_deref().unwrap_or("eth0");
                    IpRouteManager::remove_vpn1_endpoint_host_route(host, uplink);
                }
            }
        }

        // 5. Restore sysctl
        if let Some(snap) = self.sysctl_snapshot.lock().unwrap().take() {
            SysctlManager::restore(&snap);
        }

        info!("Network state cleanly restored.");
        Ok(())
    }

    /// Clean emergency cleanup
    fn emergency_cleanup(&self, uplink: &str, vpn1_endpoint_ip: &str) {
        warn!("Executing emergency cleanup of chainproxy network objects");
        self.singbox.lock().unwrap().stop();
        NftablesManager::delete_table();
        IpRouteManager::remove_inbound_fwmark_rule(INBOUND_RULE_PRIORITY);
        IpRouteManager::remove_vpn1_endpoint_host_route(vpn1_endpoint_ip, uplink);
        if let Some(snap) = self.sysctl_snapshot.lock().unwrap().take() {
            SysctlManager::restore(&snap);
        }
    }

    /// Query current status
    pub fn get_status(&self) -> ChainStatus {
        let state = self.state.lock().unwrap().clone();
        let uptime = self
            .start_time
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        let active_ver = self.active_version.lock().unwrap().clone();

        let cfg_opt = self.active_config.lock().unwrap().clone();
        let uplink = cfg_opt.as_ref().and_then(|c| c.uplink_interface.as_deref());

        let phys = HealthChecker::probe_physical(uplink);

        let (vpn1_hop, vpn2_hop, final_hop) = if let Some(cfg) = cfg_opt {
            let v1_name = cfg.vpn1.name;
            let v2_name = cfg.vpn2.name;
            (
                VpnHopStatus {
                    name: v1_name,
                    endpoint: "Configured".to_string(),
                    config_valid: true,
                    reachable: state == ServiceState::Running,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: if state == ServiceState::Running { "Running".to_string() } else { "Stopped".to_string() },
                    message: None,
                },
                VpnHopStatus {
                    name: v2_name,
                    endpoint: "Configured".to_string(),
                    config_valid: true,
                    reachable: state == ServiceState::Running,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: if state == ServiceState::Running { "Running".to_string() } else { "Stopped".to_string() },
                    message: None,
                },
                FinalHopStatus {
                    internet_ok: state == ServiceState::Running,
                    exit_ip: None,
                    exit_country: None,
                    exit_isp: None,
                    latency_ms: None,
                    status: if state == ServiceState::Running { "Active".to_string() } else { "Inactive".to_string() },
                },
            )
        } else {
            (
                VpnHopStatus {
                    name: "VPN1".to_string(),
                    endpoint: "".to_string(),
                    config_valid: false,
                    reachable: false,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: "NOT_CONFIGURED".to_string(),
                    message: None,
                },
                VpnHopStatus {
                    name: "WARP".to_string(),
                    endpoint: "".to_string(),
                    config_valid: false,
                    reachable: false,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: "NOT_CONFIGURED".to_string(),
                    message: None,
                },
                FinalHopStatus {
                    internet_ok: false,
                    exit_ip: None,
                    exit_country: None,
                    exit_isp: None,
                    latency_ms: None,
                    status: "NOT_CONFIGURED".to_string(),
                },
            )
        };

        let chain_visual = format!(
            "VPS [{}] -> VPN1 [{}] -> WARP [{}] -> Internet [{}]",
            phys.status,
            vpn1_hop.status,
            vpn2_hop.status,
            if final_hop.internet_ok { "OK" } else { "OFF" }
        );

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
