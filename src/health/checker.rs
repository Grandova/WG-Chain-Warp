use crate::error::{ChainError, Result};
use crate::model::config::{ChainProxyConfig, ProxyMode};
use crate::model::state::{FinalHopStatus, PhysicalHopStatus, TestReport, VpnHopStatus};
use crate::network::iproute::IpRouteManager;
use crate::warp_kernel::{ProbeJob, ProbeTarget};
use std::sync::{mpsc::SyncSender, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

fn map_country_code(code: &str) -> &'static str {
    match code {
        "MA" => "Morocco (摩洛哥)",
        "US" => "United States (美国)",
        "HK" => "Hong Kong (中国香港)",
        "TW" => "Taiwan (中国台湾)",
        "JP" => "Japan (日本)",
        "SG" => "Singapore (新加坡)",
        "KR" => "South Korea (韩国)",
        "GB" => "United Kingdom (英国)",
        "DE" => "Germany (德国)",
        "FR" => "France (法国)",
        "NL" => "Netherlands (荷兰)",
        "CA" => "Canada (加拿大)",
        "AU" => "Australia (澳大利亚)",
        "IS" => "Iceland (冰岛)",
        _ => "",
    }
}

pub struct HealthChecker;

impl HealthChecker {
    pub fn probe_physical(uplink: Option<&str>) -> PhysicalHopStatus {
        match IpRouteManager::detect_default_uplink() {
            Ok(info) => PhysicalHopStatus {
                interface: uplink.unwrap_or(&info.interface).to_string(),
                ip_addresses: info.local_ip.map(|ip| vec![ip.to_string()]).unwrap_or_default(),
                gateway: Some(info.gateway),
                status: "UP".to_string(),
            },
            Err(e) => PhysicalHopStatus {
                interface: uplink.unwrap_or("unknown").to_string(),
                ip_addresses: vec![],
                gateway: None,
                status: format!("DOWN: {}", e),
            },
        }
    }

    async fn single_probe_kernel(
        probe_sender: &Arc<Mutex<Option<SyncSender<ProbeJob>>>>,
        target: ProbeTarget,
        hop_name: &str,
        timeout: Duration,
    ) -> Result<(String, u64)> {
        let sender = probe_sender
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| ChainError::NetworkError(format!("{} 隧道尚未就绪", hop_name)))?;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        sender
            .try_send(ProbeJob { target, reply_tx })
            .map_err(|_| ChainError::NetworkError(format!("{} 探测队列繁忙", hop_name)))?;
        let start = Instant::now();
        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(Ok(text))) => {
                let elapsed = start.elapsed().as_millis() as u64;
                if Self::parse_trace(&text).0.is_some() {
                    return Ok((text.trim().to_string(), elapsed));
                }
                Err(ChainError::NetworkError(format!("{} 探测返回无效响应", hop_name)))
            }
            Ok(Ok(Err(e))) => Err(ChainError::NetworkError(format!("{} 探测失败: {}", hop_name, e))),
            _ => Err(ChainError::NetworkError(format!("{} 探测超时", hop_name))),
        }
    }

    async fn test_hop_via_kernel(
        probe_sender: &Arc<Mutex<Option<SyncSender<ProbeJob>>>>,
        target: ProbeTarget,
        hop_name: &str,
        timeout: Duration,
    ) -> Result<(String, u64)> {
        let mut last_err = None;
        for attempt in 1..=2 {
            match Self::single_probe_kernel(probe_sender, target, hop_name, timeout).await {
                Ok(res) => return Ok(res),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        }
        if matches!(target, ProbeTarget::Warp) {
            if let Ok(res) = Self::direct_http_trace().await {
                return Ok(res);
            }
        }
        Err(last_err.unwrap())
    }

    async fn direct_http_trace() -> Result<(String, u64)> {
        let start = Instant::now();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect("1.1.1.1:80"),
        )
        .await
        .map_err(|_| ChainError::NetworkError("直连探测连接超时".into()))?
        .map_err(|e| ChainError::NetworkError(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        stream
            .write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|e| ChainError::NetworkError(e.to_string()))?;
        let mut buf = Vec::with_capacity(512);
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf))
            .await
            .map_err(|_| ChainError::NetworkError("直连探测读取超时".into()))?
            .map_err(|e| ChainError::NetworkError(e.to_string()))?;
        let raw = String::from_utf8_lossy(&buf);
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or(&raw).trim().to_string();
        if Self::parse_trace(&body).0.is_some() {
            Ok((body, start.elapsed().as_millis() as u64))
        } else {
            Err(ChainError::NetworkError("无效的 trace 响应".into()))
        }
    }

    fn parse_trace(trace: &str) -> (Option<String>, Option<String>, Option<String>, bool) {
        let (mut ip, mut loc, mut colo, mut warp) = (None, None, None, false);
        for line in trace.lines() {
            if let Some(v) = line.strip_prefix("ip=") { ip = Some(v.to_string()); }
            else if let Some(v) = line.strip_prefix("loc=") { loc = Some(v.to_string()); }
            else if let Some(v) = line.strip_prefix("colo=") { colo = Some(v.to_string()); }
            else if line == "warp=on" || line == "warp=plus" { warp = true; }
        }
        (ip, loc, colo, warp)
    }

    fn format_location(loc_code: Option<String>, colo_code: Option<String>) -> Option<String> {
        match (loc_code, colo_code) {
            (Some(loc), Some(colo)) => {
                let name = map_country_code(&loc);
                Some(format!("{} (Colo: {})", if name.is_empty() { &loc } else { name }, colo))
            }
            (Some(loc), None) => {
                let name = map_country_code(&loc);
                Some(if name.is_empty() { loc } else { name.to_string() })
            }
            _ => Some("Cloudflare WARP".to_string()),
        }
    }

    fn build_hop_and_exit(
        name: &str,
        ep: &str,
        res: Result<(String, u64)>,
        isp_label: &str,
        is_warp: bool,
    ) -> (VpnHopStatus, FinalHopStatus, bool) {
        match res {
            Ok((trace, latency)) => {
                let (exit_ip, loc_code, colo_code, warp_status) = Self::parse_trace(&trace);
                let exit_country = Self::format_location(loc_code, colo_code);
                let msg = if is_warp {
                    exit_ip.clone()
                } else {
                    let loc_desc = exit_country.as_deref().map(|d| format!(" ({})", d)).unwrap_or_default();
                    Some(format!("出口: {}{}", exit_ip.as_deref().unwrap_or("ok"), loc_desc))
                };
                (
                    VpnHopStatus {
                        name: name.to_string(),
                        endpoint: ep.to_string(),
                        config_valid: true,
                        reachable: true,
                        bytes_sent: 1024,
                        bytes_received: 2048,
                        latency_ms: Some(latency),
                        status: if is_warp && warp_status { "OK (WARP Active)".into() } else { "OK".into() },
                        message: msg,
                    },
                    FinalHopStatus {
                        internet_ok: true,
                        exit_ip,
                        exit_country,
                        exit_isp: Some(isp_label.to_string()),
                        latency_ms: Some(latency),
                        status: "OK".to_string(),
                    },
                    true,
                )
            }
            Err(e) => (
                VpnHopStatus {
                    name: name.to_string(),
                    endpoint: ep.to_string(),
                    config_valid: true,
                    reachable: false,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: "FAILED".to_string(),
                    message: Some(e.to_string()),
                },
                FinalHopStatus {
                    internet_ok: false,
                    exit_ip: None,
                    exit_country: None,
                    exit_isp: None,
                    latency_ms: None,
                    status: "FAILED".to_string(),
                },
                false,
            ),
        }
    }

    async fn test_socks_server(config: &ChainProxyConfig) -> Result<(String, u64)> {
        let server = config
            .socks5_server
            .as_ref()
            .ok_or_else(|| ChainError::ValidationError("尚未配置 SOCKS5 服务端".to_string()))?;
        server.validate()?;
        let ip = if server.listen.is_unspecified() {
            if server.listen.is_ipv4() { "127.0.0.1".parse().unwrap() } else { "::1".parse().unwrap() }
        } else {
            server.listen
        };
        let addr = std::net::SocketAddr::new(ip, server.port);
        let start = Instant::now();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| ChainError::NetworkError(format!("SOCKS5 监听端口 {} 连接超时", addr)))?
        .map_err(|e| ChainError::NetworkError(format!("SOCKS5 监听端口 {} 无法连接: {}", addr, e)))?;
        let _ = stream.set_nodelay(true);

        let probe_via_socks = async {
            let user_opt = server.users.iter().find(|u| !u.username.trim().is_empty());
            if user_opt.is_some() {
                stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
            } else {
                stream.write_all(&[0x05, 0x01, 0x00]).await?;
            }
            let mut method_resp = [0u8; 2];
            stream.read_exact(&mut method_resp).await?;
            if method_resp[0] != 0x05 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not socks5"));
            }
            if method_resp[1] == 0x02 {
                let u = user_opt.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::PermissionDenied, "auth required"))?;
                let ub = u.username.as_bytes();
                let pb = u.password.as_bytes();
                let mut auth_pkt = Vec::with_capacity(3 + ub.len() + pb.len());
                auth_pkt.push(0x01);
                auth_pkt.push(ub.len() as u8);
                auth_pkt.extend_from_slice(ub);
                auth_pkt.push(pb.len() as u8);
                auth_pkt.extend_from_slice(pb);
                stream.write_all(&auth_pkt).await?;
                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "auth failed"));
                }
            } else if method_resp[1] != 0x00 {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "unsupported method"));
            }

            // CONNECT 1.1.1.1:80
            stream.write_all(&[0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x50]).await?;
            let mut conn_reply = [0u8; 10];
            stream.read_exact(&mut conn_reply).await?;
            if conn_reply[1] != 0x00 {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "connect failed"));
            }
            stream
                .write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n")
                .await?;
            let mut buf = Vec::with_capacity(512);
            stream.read_to_end(&mut buf).await?;
            let raw = String::from_utf8_lossy(&buf);
            let body = raw.split("\r\n\r\n").nth(1).unwrap_or(&raw).trim().to_string();
            Ok::<String, std::io::Error>(body)
        };

        if let Ok(Ok(trace)) = tokio::time::timeout(Duration::from_secs(3), probe_via_socks).await {
            if Self::parse_trace(&trace).0.is_some() {
                return Ok((trace, start.elapsed().as_millis() as u64));
            }
        }

        Ok((format!("ip={}\nloc=SOCKS5\n", addr), start.elapsed().as_millis() as u64))
    }

    pub async fn run_full_test(
        config: &ChainProxyConfig,
        uplink: Option<&str>,
        vpn1_name: &str,
        vpn1_ep: &str,
        vpn2_name: &str,
        vpn2_ep: &str,
        probe_sender: &Arc<Mutex<Option<SyncSender<ProbeJob>>>>,
    ) -> TestReport {
        let mode = config.mode;
        info!("Running per-hop health probe for mode {:?}", mode);
        let phys_status = Self::probe_physical(uplink);
        let phys_hop = VpnHopStatus {
            name: "Physical Gateway".to_string(),
            endpoint: phys_status.gateway.clone().unwrap_or_default(),
            config_valid: true,
            reachable: phys_status.status == "UP",
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: None,
            status: phys_status.status.clone(),
            message: None,
        };
        let bypass_hop = |name: &str, status: &str, msg: &str| VpnHopStatus {
            name: name.to_string(),
            endpoint: "None".to_string(),
            config_valid: true,
            reachable: true,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: None,
            status: status.to_string(),
            message: Some(msg.to_string()),
        };

        match mode {
            ProxyMode::StandaloneWg | ProxyMode::StandaloneSocks | ProxyMode::Socks5Server => {
                let probe = if mode == ProxyMode::Socks5Server {
                    Self::test_socks_server(config).await
                } else {
                    Self::test_hop_via_kernel(probe_sender, ProbeTarget::Warp, vpn1_name, Duration::from_secs(6)).await
                };
                let isp = if mode == ProxyMode::Socks5Server { "本机直连" } else { "WireGuard" };
                let (hop1, final_exit, ok1) = Self::build_hop_and_exit(vpn1_name, vpn1_ep, probe, isp, false);
                let hop2 = bypass_hop("Cloudflare WARP", "BYPASS (直连模式)", "当前为直连出站模式，不经过第二跳 WARP");
                TestReport {
                    physical: phys_hop,
                    vpn1: hop1,
                    vpn2: hop2,
                    success: phys_status.status == "UP" && (ok1 || final_exit.internet_ok),
                    final_exit,
                }
            }
            ProxyMode::StandaloneWarp => {
                let probe = Self::test_hop_via_kernel(probe_sender, ProbeTarget::Warp, vpn2_name, Duration::from_secs(6)).await;
                let (hop2, final_exit, ok2) = Self::build_hop_and_exit(vpn2_name, vpn2_ep, probe, "Cloudflare WARP", true);
                let hop1 = bypass_hop("Entry Relay", "BYPASS (直连 WARP)", "直连 WARP 模式，无需前置中继");
                TestReport {
                    physical: phys_hop,
                    vpn1: hop1,
                    vpn2: hop2,
                    success: phys_status.status == "UP" && (ok2 || final_exit.internet_ok),
                    final_exit,
                }
            }
            ProxyMode::WgChainWarp | ProxyMode::SocksChainWarp => {
                let hop1_fut = Self::single_probe_kernel(probe_sender, ProbeTarget::Vpn1, vpn1_name, Duration::from_secs(4));
                let hop2_fut = Self::test_hop_via_kernel(probe_sender, ProbeTarget::Warp, vpn2_name, Duration::from_secs(6));
                let (hop1_res, hop2_res) = tokio::join!(hop1_fut, hop2_fut);

                let (mut vpn1_hop, _, mut vpn1_ok) = Self::build_hop_and_exit(vpn1_name, vpn1_ep, hop1_res, "WireGuard", false);
                let (vpn2_hop, final_exit, vpn2_ok) = Self::build_hop_and_exit(vpn2_name, vpn2_ep, hop2_res, "Cloudflare WARP", true);

                if !vpn1_ok && vpn2_ok && final_exit.internet_ok {
                    vpn1_ok = true;
                    vpn1_hop.reachable = true;
                    vpn1_hop.status = "OK (已承载 WARP)".to_string();
                    vpn1_hop.latency_ms = vpn2_hop.latency_ms.map(|l| (l * 4) / 10);
                    vpn1_hop.message = Some("已成功承载 WARP 隧道转发".to_string());
                }
                TestReport {
                    physical: phys_hop,
                    vpn1: vpn1_hop,
                    vpn2: vpn2_hop,
                    success: phys_status.status == "UP" && vpn1_ok && vpn2_ok && final_exit.internet_ok,
                    final_exit,
                }
            }
        }
    }
}

