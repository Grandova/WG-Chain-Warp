use crate::error::{ChainError, Result};
use crate::health::checker::HealthChecker;
use crate::model::config::{ChainProxyConfig, ProxyMode};
use crate::model::state::{
    ChainStatus, FinalHopStatus, PhysicalHopStatus, ServiceState, TestReport, VpnHopStatus,
};
use crate::network::iproute::{IpRouteManager, RoutePlan};
use crate::network::nftables::NftablesManager;
use crate::network::sysctl::{SysctlManager, SysctlSnapshot};
use crate::warp_kernel::{WarpKernel, TEST_WARP_PORT};
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
}

impl NetworkSnapshot {
    pub fn capture(plan: RoutePlan, config: &ChainProxyConfig) -> Result<Self> {
        let inbound_mark = if config.routing.preserve_inbound_connections {
            config.routing.inbound_mark()?
        } else {
            0
        };
        if inbound_mark != 0 {
            let probe = std::process::Command::new("conntrack").arg("-C").output()?;
            if !probe.status.success() {
                return Err(ChainError::NetworkError(String::from_utf8_lossy(&probe.stderr).into_owned()));
            }
        }
        Ok(Self {
            plan,
            nft: NftablesManager::snapshot()?,
            sysctl: SysctlManager::snapshot()?,
            inbound_mark,
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

#[derive(Clone)]
pub struct ChainEngine {
    base_dir: PathBuf,
    warp_kernel: Arc<Mutex<WarpKernel>>,
    network_snapshot: Arc<Mutex<Option<NetworkSnapshot>>>,
    active_config: Arc<Mutex<Option<ChainProxyConfig>>>,
    state: Arc<Mutex<ServiceState>>,
    start_time: Arc<Mutex<Option<Instant>>>,
    watchdog_timeout_secs: Arc<AtomicU64>,
    cached_physical: Arc<Mutex<Option<(Instant, PhysicalHopStatus)>>>,
    last_report: Arc<Mutex<Option<TestReport>>>,
}

impl ChainEngine {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        let base_path = base_dir.as_ref().to_path_buf();
        let cfg_file = base_path.join("config.json");
        let initial_config = std::fs::read_to_string(&cfg_file)
            .ok()
            .and_then(|c| serde_json::from_str::<ChainProxyConfig>(&c).ok());

        Self {
            base_dir: base_path,
            warp_kernel: Arc::new(Mutex::new(WarpKernel::new())),
            network_snapshot: Arc::new(Mutex::new(None)),
            active_config: Arc::new(Mutex::new(initial_config)),
            state: Arc::new(Mutex::new(ServiceState::Stopped)),
            start_time: Arc::new(Mutex::new(None)),
            watchdog_timeout_secs: Arc::new(AtomicU64::new(30)),
            cached_physical: Arc::new(Mutex::new(None)),
            last_report: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_watchdog_timeout(&self, secs: u64) {
        self.watchdog_timeout_secs.store(secs, Ordering::SeqCst);
    }

    pub fn update_last_report(&self, report: TestReport) {
        *self.last_report.lock().unwrap() = Some(report);
    }

    fn get_cached_physical(&self, uplink: Option<&str>) -> PhysicalHopStatus {
        let mut guard = self.cached_physical.lock().unwrap();
        if let Some((ts, ref status)) = *guard {
            if ts.elapsed() < Duration::from_secs(60) {
                return status.clone();
            }
        }
        let fresh = HealthChecker::probe_physical(uplink);
        *guard = Some((Instant::now(), fresh.clone()));
        fresh
    }

    pub async fn apply(&mut self, config: ChainProxyConfig) -> Result<TestReport> {
        let parsed = config.parse_and_validate()?;
        let uplink = match &config.uplink_interface {
            Some(iface) => iface.clone(),
            None => IpRouteManager::detect_default_uplink()?.interface,
        };
        let local_ip = IpRouteManager::get_interface_ipv4(&uplink)?.to_string();
        let plan = if config.mode == ProxyMode::Socks5Server {
            RoutePlan::default()
        } else {
            IpRouteManager::route_plan(&config, &IpRouteManager::detect_current_ssh_client_ips())?
        };
        let nft_rules = if config.mode == ProxyMode::Socks5Server {
            String::new()
        } else {
            NftablesManager::generate_ruleset(&config)?
        };

        let previous = if *self.state.lock().unwrap() == ServiceState::Running {
            self.active_config.lock().unwrap().clone()
        } else {
            None
        };
        self.stop()?;
        *self.state.lock().unwrap() = ServiceState::Starting;
        let timeout = Duration::from_secs(self.watchdog_timeout_secs.load(Ordering::SeqCst));
        let result = tokio::time::timeout(timeout, async {
            std::fs::create_dir_all(&self.base_dir)?;
            if config.mode != ProxyMode::Socks5Server {
                IpRouteManager::check_available(&plan)?;
                if IpRouteManager::interface_exists("chain0") {
                    return Err(ChainError::NetworkError("chain0 already exists".into()));
                }
                let snapshot = NetworkSnapshot::capture(plan, &config)?;
                let journal = self.base_dir.join("network_snapshot.json");
                let mut file = tempfile::NamedTempFile::new_in(&self.base_dir)?;
                file.write_all(&serde_json::to_vec(&snapshot)?)?;
                file.as_file().sync_all()?;
                file.persist(&journal).map_err(|e| e.error)?;
                *self.network_snapshot.lock().unwrap() = Some(snapshot);

                SysctlManager::configure_for_proxy(&[uplink.clone()], false, config.routing.ipv6)?;
                let plan_clone = self.network_snapshot.lock().unwrap().as_ref().unwrap().plan.clone();
                IpRouteManager::install_rules(&plan_clone)?;
                IpRouteManager::ensure_tun_device()?;
            }

            self.warp_kernel.lock().unwrap().start(&config, &parsed, &uplink, &local_ip)?;

            if config.mode != ProxyMode::Socks5Server {
                if !IpRouteManager::wait_for_interface("chain0", Duration::from_secs(5)) {
                    return Err(ChainError::NetworkError("chain0 did not appear within 5s".into()));
                }
                SysctlManager::configure_tun_sysctl("chain0")?;
                let plan_clone = self.network_snapshot.lock().unwrap().as_ref().unwrap().plan.clone();
                IpRouteManager::install_routes(&plan_clone)?;
                NftablesManager::apply_ruleset(&nft_rules)?;

                let wait_start = Instant::now();
                let test_addr = format!("127.0.0.1:{}", TEST_WARP_PORT);
                while wait_start.elapsed() < Duration::from_millis(1500) {
                    if tokio::net::TcpStream::connect(&test_addr).await.is_ok() { break; }
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            } else {
                tokio::time::sleep(Duration::from_millis(80)).await;
            }

            let (v1_name, v1_ep) = match config.mode {
                ProxyMode::Socks5Server => (
                    "SOCKS5 服务端".into(),
                    config.socks5_server.as_ref().map(|s| std::net::SocketAddr::new(s.listen, s.port).to_string()).unwrap_or_default(),
                ),
                ProxyMode::SocksChainWarp | ProxyMode::StandaloneSocks => (
                    parsed.socks5.as_ref().map(|s| s.redacted_string()).unwrap_or_default(),
                    parsed.socks5.as_ref().map(|s| format!("{}:{}", s.server, s.port)).unwrap_or_default(),
                ),
                _ => (
                    config.vpn1.name.clone(),
                    parsed.vpn1.as_ref().and_then(|p| p.peers.first()?.endpoint.as_ref()).map(|e| e.to_string()).unwrap_or_default(),
                ),
            };
            let v2_ep = parsed
                .vpn2
                .as_ref()
                .and_then(|p| p.peers.first()?.endpoint.as_ref())
                .map(|e| e.to_string())
                .unwrap_or_default();

            let mut report = HealthChecker::run_full_test(&config, Some(&uplink), &v1_name, &v1_ep, &config.vpn2.name, &v2_ep).await;
            let kstats = self.warp_kernel.lock().unwrap().stats();
            if let Some(active_ep) = kstats.active_warp_endpoint {
                report.vpn2.endpoint = active_ep;
            }

            if !report.success || !self.warp_kernel.lock().unwrap().is_running() {
                return Err(ChainError::TransactionError {
                    stage: "TEST".into(),
                    message: "Proxy health check failed".into(),
                });
            }
            self.save_config(config)?;
            *self.state.lock().unwrap() = ServiceState::Running;
            *self.start_time.lock().unwrap() = Some(Instant::now());
            *self.last_report.lock().unwrap() = Some(report.clone());
            Ok(report)
        })
        .await
        .unwrap_or_else(|_| {
            Err(ChainError::TransactionError {
                stage: "WATCHDOG".into(),
                message: "Apply timed out; restoring previous network".into(),
            })
        });

        if let Err(error) = result {
            *self.state.lock().unwrap() = ServiceState::RollingBack;
            self.stop()?;
            *self.state.lock().unwrap() = ServiceState::Failed;
            if let Some(previous) = previous {
                if let Err(restore_error) = Box::pin(self.apply(previous)).await {
                    return Err(ChainError::TransactionError {
                        stage: "ROLLBACK".into(),
                        message: format!("{}; previous config also failed: {}", error, restore_error),
                    });
                }
            }
            return Err(error);
        }
        result
    }

    pub fn stop(&mut self) -> Result<()> {
        let journal = self.base_dir.join("network_snapshot.json");
        {
            let mut snap_guard = self.network_snapshot.lock().unwrap();
            if snap_guard.is_none() && journal.exists() {
                *snap_guard = Some(serde_json::from_slice(&std::fs::read(&journal)?)?);
            }
        }
        if let Some(snapshot) = self.network_snapshot.lock().unwrap().take() {
            let nft = NftablesManager::restore(None);
            self.warp_kernel.lock().unwrap().stop();
            let restored = snapshot.restore();
            nft.and(restored)?;
            if journal.exists() {
                std::fs::remove_file(&journal)?;
            }
        } else {
            self.warp_kernel.lock().unwrap().stop();
        }
        *self.state.lock().unwrap() = ServiceState::Stopped;
        *self.start_time.lock().unwrap() = None;
        *self.last_report.lock().unwrap() = None;
        info!("Original network state restored");
        Ok(())
    }

    pub fn get_status(&self) -> ChainStatus {
        let state = self.state.lock().unwrap().clone();
        let uptime = self.start_time.lock().unwrap().map(|t| t.elapsed().as_secs()).unwrap_or(0);
        let cfg_opt = self.active_config.lock().unwrap().clone();
        let uplink = cfg_opt.as_ref().and_then(|c| c.uplink_interface.as_deref());
        let phys = self.get_cached_physical(uplink);
        let cached_rep = self.last_report.lock().unwrap().clone();
        let kstats = self.warp_kernel.lock().unwrap().stats();

        let status_str = |configured: bool| -> String {
            if !configured { "未配置".into() }
            else if state == ServiceState::Running { "运行中".into() }
            else if state == ServiceState::Failed { "启动失败".into() }
            else { "待启动".into() }
        };

        let (vpn1_hop, vpn2_hop, final_hop) = if let Some(ref cfg) = cfg_opt {
            let v1_cfg = match cfg.mode {
                ProxyMode::Socks5Server => cfg.socks5_server.is_some(),
                ProxyMode::SocksChainWarp | ProxyMode::StandaloneSocks => cfg.socks5.is_some(),
                _ => !cfg.vpn1.wireguard_config.trim().is_empty(),
            };
            let uses_v2 = !matches!(cfg.mode, ProxyMode::StandaloneWg | ProxyMode::StandaloneSocks | ProxyMode::Socks5Server);
            let v2_cfg = uses_v2 && !cfg.vpn2.wireguard_config.trim().is_empty();

            let (v1_name, v1_ep) = match cfg.mode {
                ProxyMode::Socks5Server => (
                    "SOCKS5 服务端".into(),
                    cfg.socks5_server.as_ref().map(|s| std::net::SocketAddr::new(s.listen, s.port).to_string()).unwrap_or_default(),
                ),
                ProxyMode::SocksChainWarp | ProxyMode::StandaloneSocks => (
                    cfg.socks5.as_ref().map(|s| s.redacted_string()).unwrap_or_else(|| "Socks5 节点".into()),
                    cfg.socks5.as_ref().map(|s| format!("{}:{}", s.server, s.port)).unwrap_or_default(),
                ),
                _ => (
                    if cfg.vpn1.name.is_empty() { "WireGuard 节点".into() } else { cfg.vpn1.name.clone() },
                    cached_rep.as_ref().map(|r| r.vpn1.endpoint.clone()).unwrap_or_else(|| if v1_cfg { "已就绪".into() } else { "".into() }),
                ),
            };

            let (v2_name, v2_ep) = if !uses_v2 {
                ("Cloudflare WARP (未使用)".into(), "".into())
            } else {
                (
                    if cfg.vpn2.name.is_empty() { "Cloudflare WARP".into() } else { cfg.vpn2.name.clone() },
                    kstats.active_warp_endpoint.or_else(|| cached_rep.as_ref().map(|r| r.vpn2.endpoint.clone())).unwrap_or_else(|| if v2_cfg { "已就绪".into() } else { "".into() }),
                )
            };

            let f_hop = if state == ServiceState::Running {
                cached_rep.as_ref().map(|r| r.final_exit.clone()).unwrap_or(FinalHopStatus {
                    internet_ok: true, exit_ip: None, exit_country: None, exit_isp: None, latency_ms: None, status: "正常".into(),
                })
            } else {
                FinalHopStatus {
                    internet_ok: false, exit_ip: None, exit_country: None, exit_isp: None, latency_ms: None, status: "离线".into(),
                }
            };

            (
                VpnHopStatus {
                    name: v1_name,
                    endpoint: v1_ep,
                    config_valid: v1_cfg,
                    reachable: state == ServiceState::Running && v1_cfg,
                    bytes_sent: kstats.vpn1_tx,
                    bytes_received: kstats.vpn1_rx,
                    latency_ms: cached_rep.as_ref().and_then(|r| r.vpn1.latency_ms),
                    status: status_str(v1_cfg),
                    message: None,
                },
                VpnHopStatus {
                    name: v2_name,
                    endpoint: v2_ep,
                    config_valid: v2_cfg,
                    reachable: state == ServiceState::Running && v2_cfg,
                    bytes_sent: kstats.warp_tx,
                    bytes_received: kstats.warp_rx,
                    latency_ms: cached_rep.as_ref().and_then(|r| r.vpn2.latency_ms),
                    status: if !uses_v2 { "未使用".into() } else { status_str(v2_cfg) },
                    message: None,
                },
                f_hop,
            )
        } else {
            let empty_hop = |name: &str| VpnHopStatus {
                name: name.into(), endpoint: "".into(), config_valid: false, reachable: false,
                bytes_sent: 0, bytes_received: 0, latency_ms: None, status: "未配置".into(), message: None,
            };
            (
                empty_hop("WireGuard / 入口节点"),
                empty_hop("Cloudflare WARP"),
                FinalHopStatus { internet_ok: false, exit_ip: None, exit_country: None, exit_isp: None, latency_ms: None, status: "离线".into() },
            )
        };

        let net_ok = if final_hop.internet_ok { "正常 (OK)" } else { "离线 (OFF)" };
        let chain_visual = match cfg_opt.as_ref().map(|c| c.mode) {
            Some(ProxyMode::Socks5Server) => format!("客户端 -> SOCKS5 [{}] -> 本机直连 [{}]", vpn1_hop.status, net_ok),
            Some(ProxyMode::WgChainWarp) => format!("VPS [{}] -> WireGuard [{}] -> WARP [{}] -> 目标公网 [{}]", phys.status, vpn1_hop.status, vpn2_hop.status, net_ok),
            Some(ProxyMode::SocksChainWarp) => format!("VPS [{}] -> Socks5 [{}] -> WARP [{}] -> 目标公网 [{}]", phys.status, vpn1_hop.status, vpn2_hop.status, net_ok),
            Some(ProxyMode::StandaloneWg) => format!("VPS [{}] -> WireGuard [{}] -> 目标公网 [{}]", phys.status, vpn1_hop.status, net_ok),
            Some(ProxyMode::StandaloneSocks) => format!("VPS [{}] -> Socks5 [{}] -> 目标公网 [{}]", phys.status, vpn1_hop.status, net_ok),
            Some(ProxyMode::StandaloneWarp) => format!("VPS [{}] -> WARP [{}] -> 目标公网 [{}]", phys.status, vpn2_hop.status, net_ok),
            None => format!("VPS [{}] -> 入口 [未配置] -> 出口 [未配置] -> 目标公网 [离线 (OFF)]", phys.status),
        };

        ChainStatus {
            active_config_version: (state == ServiceState::Running).then(|| "WarpKernel".to_string()),
            state,
            uptime_seconds: uptime,
            physical: phys,
            vpn1: vpn1_hop,
            vpn2: vpn2_hop,
            final_hop,
            chain_visual,
        }
    }

    pub fn get_active_config(&self) -> Option<ChainProxyConfig> {
        if let Some(cfg) = self.active_config.lock().unwrap().clone() {
            return Some(cfg);
        }
        let cfg_path = self.base_dir.join("config.json");
        let parsed = std::fs::read_to_string(&cfg_path)
            .ok()
            .and_then(|c| serde_json::from_str::<ChainProxyConfig>(&c).ok())?;
        *self.active_config.lock().unwrap() = Some(parsed.clone());
        Some(parsed)
    }

    pub fn save_config(&self, config: ChainProxyConfig) -> Result<()> {
        std::fs::create_dir_all(&self.base_dir)?;
        let cfg_path = self.base_dir.join("config.json");
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&config)?)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600));
        }
        *self.active_config.lock().unwrap() = Some(config);
        Ok(())
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}
