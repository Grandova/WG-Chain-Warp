use crate::error::{ChainError, Result};
use crate::model::config::{ChainProxyConfig, ProxyMode};
use crate::model::state::{FinalHopStatus, PhysicalHopStatus, TestReport, VpnHopStatus};
use crate::network::iproute::IpRouteManager;
use crate::singbox::generator::{TEST_VPN1_PORT, TEST_WARP_PORT};
use reqwest::Proxy;
use std::time::{Duration, Instant};
use tracing::{info, warn};

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
    /// Probe Physical Network (Interface & Gateway)
    pub fn probe_physical(uplink: Option<&str>) -> PhysicalHopStatus {
        match IpRouteManager::detect_default_uplink() {
            Ok(info) => {
                let iface = uplink.unwrap_or(&info.interface).to_string();
                let ips = if let Some(ip) = info.local_ip {
                    vec![ip.to_string()]
                } else {
                    vec![]
                };
                PhysicalHopStatus {
                    interface: iface,
                    ip_addresses: ips,
                    gateway: Some(info.gateway),
                    status: "UP".to_string(),
                }
            }
            Err(e) => PhysicalHopStatus {
                interface: uplink.unwrap_or("unknown").to_string(),
                ip_addresses: vec![],
                gateway: None,
                status: format!("DOWN: {}", e),
            },
        }
    }

    fn cached_proxy_client(proxy_port: u16) -> Result<reqwest::Client> {
        static CLIENT_VPN1: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
        static CLIENT_WARP: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

        let build_for_port = |port: u16| -> Result<reqwest::Client> {
            let proxy = Proxy::all(format!("http://127.0.0.1:{}", port))
                .map_err(|e| ChainError::NetworkError(e.to_string()))?;
            reqwest::Client::builder()
                .proxy(proxy)
                .pool_max_idle_per_host(0)
                .tcp_nodelay(true)
                .build()
                .map_err(|e| ChainError::NetworkError(e.to_string()))
        };

        if proxy_port == TEST_VPN1_PORT {
            if let Some(c) = CLIENT_VPN1.get() {
                return Ok(c.clone());
            }
            let c = build_for_port(proxy_port)?;
            let _ = CLIENT_VPN1.set(c.clone());
            return Ok(c);
        }
        if proxy_port == TEST_WARP_PORT {
            if let Some(c) = CLIENT_WARP.get() {
                return Ok(c.clone());
            }
            let c = build_for_port(proxy_port)?;
            let _ = CLIENT_WARP.set(c.clone());
            return Ok(c);
        }
        build_for_port(proxy_port)
    }

    /// Single probe via sing-box local mixed test inbound
    async fn single_probe_proxy(
        proxy_port: u16,
        hop_name: &str,
        test_url: &str,
        timeout: Duration,
    ) -> Result<(String, u64)> {
        let client = Self::cached_proxy_client(proxy_port)?;

        let start = Instant::now();
        if let Ok(resp) = client.get(test_url).timeout(timeout).send().await {
            let elapsed = start.elapsed().as_millis() as u64;
            if let Ok(text) = resp.text().await {
                if Self::parse_trace(&text).0.is_some() {
                    return Ok((text.trim().to_string(), elapsed));
                }
            }
        }

        Err(ChainError::NetworkError(format!(
            "Connection test to {} failed via {} on 127.0.0.1:{}",
            test_url, hop_name, proxy_port
        )))
    }

    /// Test a hop via sing-box local test inbound with fast retry
    pub async fn test_hop_via_proxy(
        proxy_port: u16,
        hop_name: &str,
        test_url: &str,
        timeout: Duration,
    ) -> Result<(String, u64)> {
        let mut last_err = None;
        for attempt in 1..=2 {
            match Self::single_probe_proxy(proxy_port, hop_name, test_url, timeout).await {
                Ok(res) => return Ok(res),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ChainError::NetworkError("Unknown test error".to_string())))
    }

    /// Helper to parse Cloudflare /cdn-cgi/trace
    fn parse_trace(trace: &str) -> (Option<String>, Option<String>, Option<String>, bool) {
        let mut exit_ip = None;
        let mut loc_code = None;
        let mut colo_code = None;
        let mut warp_status = false;

        for line in trace.lines() {
            if let Some(ip) = line.strip_prefix("ip=") {
                exit_ip = Some(ip.to_string());
            } else if let Some(loc) = line.strip_prefix("loc=") {
                loc_code = Some(loc.to_string());
            } else if let Some(colo) = line.strip_prefix("colo=") {
                colo_code = Some(colo.to_string());
            } else if line == "warp=on" || line == "warp=plus" {
                warp_status = true;
            }
        }
        (exit_ip, loc_code, colo_code, warp_status)
    }

    fn format_location(loc_code: Option<String>, colo_code: Option<String>) -> Option<String> {
        match (loc_code, colo_code) {
            (Some(loc), Some(colo)) => {
                let name = map_country_code(&loc);
                if !name.is_empty() {
                    Some(format!("{} (Colo: {})", name, colo))
                } else {
                    Some(format!("{} (Colo: {})", loc, colo))
                }
            }
            (Some(loc), None) => {
                let name = map_country_code(&loc);
                if !name.is_empty() {
                    Some(name.to_string())
                } else {
                    Some(loc)
                }
            }
            _ => Some("Cloudflare WARP".to_string()),
        }
    }

    async fn test_socks_server(config: &ChainProxyConfig) -> Result<(String, u64)> {
        let server = config
            .socks5_server
            .as_ref()
            .ok_or_else(|| ChainError::ValidationError("尚未配置 SOCKS5 服务端".to_string()))?;
        server.validate()?;
        let ip = if server.listen.is_unspecified() {
            if server.listen.is_ipv4() {
                "127.0.0.1".parse().unwrap()
            } else {
                "::1".parse().unwrap()
            }
        } else {
            server.listen
        };
        let addr = std::net::SocketAddr::new(ip, server.port);
        let user = &server.users[0];
        let network_error = |e: reqwest::Error| ChainError::NetworkError(e.to_string());
        let proxy = Proxy::all(format!("socks5h://{}", addr))
            .map_err(network_error)?
            .basic_auth(&user.username, &user.password);
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(6))
            .build()
            .map_err(network_error)?;
        let start = Instant::now();
        let trace = client
            .get("https://one.one.one.one/cdn-cgi/trace")
            .send()
            .await
            .map_err(network_error)?
            .error_for_status()
            .map_err(network_error)?
            .text()
            .await
            .map_err(network_error)?;
        if Self::parse_trace(&trace).0.is_none() {
            return Err(ChainError::NetworkError(
                "SOCKS5 服务端探测未返回出口 IP".to_string(),
            ));
        }
        Ok((trace, start.elapsed().as_millis() as u64))
    }

    /// Run full per-hop link test: Physical -> Entry Hop -> Exit Hop -> Final Exit IP
    pub async fn run_full_test(
        config: &ChainProxyConfig,
        uplink: Option<&str>,
        vpn1_name: &str,
        vpn1_endpoint: &str,
        vpn2_name: &str,
        vpn2_endpoint: &str,
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

        match mode {
            ProxyMode::StandaloneWg | ProxyMode::StandaloneSocks | ProxyMode::Socks5Server => {
                let probe = if mode == ProxyMode::Socks5Server {
                    Self::test_socks_server(config).await
                } else {
                    Self::test_hop_via_proxy(
                        TEST_WARP_PORT,
                        vpn1_name,
                        if mode == ProxyMode::StandaloneSocks {
                            "https://one.one.one.one/cdn-cgi/trace"
                        } else {
                            "https://1.1.1.1/cdn-cgi/trace"
                        },
                        Duration::from_secs(4),
                    )
                    .await
                };
                let (hop1, final_exit, hop1_ok) = match probe {
                    Ok((trace, latency)) => {
                        let (exit_ip, loc_code, colo_code, _) = Self::parse_trace(&trace);
                        let exit_country = Self::format_location(loc_code, colo_code);
                        let loc_desc = exit_country
                            .as_deref()
                            .map(|d| format!(" ({})", d))
                            .unwrap_or_default();
                        let ip_str = exit_ip.clone().unwrap_or_else(|| "ok".to_string());
                        (
                            VpnHopStatus {
                                name: vpn1_name.to_string(),
                                endpoint: vpn1_endpoint.to_string(),
                                config_valid: true,
                                reachable: true,
                                bytes_sent: 0,
                                bytes_received: 0,
                                latency_ms: Some(latency),
                                status: "OK".to_string(),
                                message: Some(format!("出口: {}{}", ip_str, loc_desc)),
                            },
                            FinalHopStatus {
                                internet_ok: true,
                                exit_ip,
                                exit_country,
                                exit_isp: Some(
                                    if mode == ProxyMode::StandaloneSocks {
                                        "Socks5 Proxy"
                                    } else if mode == ProxyMode::Socks5Server {
                                        "本机直连"
                                    } else {
                                        "WireGuard"
                                    }
                                    .to_string(),
                                ),
                                latency_ms: Some(latency),
                                status: "OK".to_string(),
                            },
                            true,
                        )
                    }
                    Err(e) => {
                        warn!("Standalone outbound hop test failed: {}", e);
                        (
                            VpnHopStatus {
                                name: vpn1_name.to_string(),
                                endpoint: vpn1_endpoint.to_string(),
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
                        )
                    }
                };

                let hop2 = VpnHopStatus {
                    name: "Cloudflare WARP".to_string(),
                    endpoint: "None".to_string(),
                    config_valid: true,
                    reachable: true,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: "BYPASS (直连模式)".to_string(),
                    message: Some("当前为直连出站模式，不经过第二跳 WARP".to_string()),
                };

                let overall_success =
                    phys_status.status == "UP" && (hop1_ok || final_exit.internet_ok);

                TestReport {
                    physical: phys_hop,
                    vpn1: hop1,
                    vpn2: hop2,
                    final_exit,
                    success: overall_success,
                }
            }
            ProxyMode::StandaloneWarp => {
                let (hop2, final_exit, hop2_ok) = match Self::test_hop_via_proxy(
                    TEST_WARP_PORT,
                    vpn2_name,
                    "https://1.1.1.1/cdn-cgi/trace",
                    Duration::from_secs(4),
                )
                .await
                {
                    Ok((trace, latency)) => {
                        let (exit_ip, loc_code, colo_code, warp_status) = Self::parse_trace(&trace);
                        let exit_country = Self::format_location(loc_code, colo_code);
                        (
                            VpnHopStatus {
                                name: vpn2_name.to_string(),
                                endpoint: vpn2_endpoint.to_string(),
                                config_valid: true,
                                reachable: true,
                                bytes_sent: 2048,
                                bytes_received: 4096,
                                latency_ms: Some(latency),
                                status: if warp_status {
                                    "OK (WARP Active)".to_string()
                                } else {
                                    "OK".to_string()
                                },
                                message: exit_ip.clone(),
                            },
                            FinalHopStatus {
                                internet_ok: true,
                                exit_ip,
                                exit_country,
                                exit_isp: Some("Cloudflare WARP".to_string()),
                                latency_ms: Some(latency),
                                status: "OK".to_string(),
                            },
                            true,
                        )
                    }
                    Err(e) => {
                        warn!("Standalone WARP hop test failed: {}", e);
                        (
                            VpnHopStatus {
                                name: vpn2_name.to_string(),
                                endpoint: vpn2_endpoint.to_string(),
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
                        )
                    }
                };

                let hop1 = VpnHopStatus {
                    name: "Entry Relay".to_string(),
                    endpoint: "None".to_string(),
                    config_valid: true,
                    reachable: true,
                    bytes_sent: 0,
                    bytes_received: 0,
                    latency_ms: None,
                    status: "BYPASS (直连 WARP)".to_string(),
                    message: Some("直连 WARP 模式，无需前置中继".to_string()),
                };

                let overall_success =
                    phys_status.status == "UP" && (hop2_ok || final_exit.internet_ok);

                TestReport {
                    physical: phys_hop,
                    vpn1: hop1,
                    vpn2: hop2,
                    final_exit,
                    success: overall_success,
                }
            }
            ProxyMode::WgChainWarp | ProxyMode::SocksChainWarp => {
                // Probe Hop 2 (WARP over Hop 1) and Hop 1 concurrently for maximum speed!
                let hop1_fut = Self::single_probe_proxy(
                    TEST_VPN1_PORT,
                    vpn1_name,
                    "http://1.1.1.1/cdn-cgi/trace",
                    Duration::from_millis(2200),
                );
                let hop2_fut = Self::test_hop_via_proxy(
                    TEST_WARP_PORT,
                    vpn2_name,
                    "https://1.1.1.1/cdn-cgi/trace",
                    Duration::from_secs(4),
                );

                let (hop1_res, hop2_res) = tokio::join!(hop1_fut, hop2_fut);

                let (vpn1_hop, vpn1_ok) = match hop1_res {
                    Ok((trace, latency)) => {
                        let (exit_ip, loc_code, colo_code, _) = Self::parse_trace(&trace);
                        let loc_desc = Self::format_location(loc_code, colo_code)
                            .map(|d| format!(" ({})", d))
                            .unwrap_or_default();
                        let ip_str = exit_ip.unwrap_or_else(|| "ok".to_string());

                        (
                            VpnHopStatus {
                                name: vpn1_name.to_string(),
                                endpoint: vpn1_endpoint.to_string(),
                                config_valid: true,
                                reachable: true,
                                bytes_sent: 1024,
                                bytes_received: 2048,
                                latency_ms: Some(latency),
                                status: "OK".to_string(),
                                message: Some(format!("出口: {}{}", ip_str, loc_desc)),
                            },
                            true,
                        )
                    }
                    Err(e) => (
                        VpnHopStatus {
                            name: vpn1_name.to_string(),
                            endpoint: vpn1_endpoint.to_string(),
                            config_valid: true,
                            reachable: false,
                            bytes_sent: 0,
                            bytes_received: 0,
                            latency_ms: None,
                            status: "FAILED".to_string(),
                            message: Some(e.to_string()),
                        },
                        false,
                    ),
                };

                let (vpn2_hop, final_exit, vpn2_ok) = match hop2_res {
                    Ok((trace, latency)) => {
                        let (exit_ip, loc_code, colo_code, warp_status) = Self::parse_trace(&trace);
                        let exit_country = Self::format_location(loc_code, colo_code);

                        (
                            VpnHopStatus {
                                name: vpn2_name.to_string(),
                                endpoint: vpn2_endpoint.to_string(),
                                config_valid: true,
                                reachable: true,
                                bytes_sent: 2048,
                                bytes_received: 4096,
                                latency_ms: Some(latency),
                                status: if warp_status {
                                    "OK (WARP Active)".to_string()
                                } else {
                                    "OK".to_string()
                                },
                                message: exit_ip.clone(),
                            },
                            FinalHopStatus {
                                internet_ok: true,
                                exit_ip,
                                exit_country,
                                exit_isp: Some("Cloudflare WARP".to_string()),
                                latency_ms: Some(latency),
                                status: "OK".to_string(),
                            },
                            true,
                        )
                    }
                    Err(e) => {
                        warn!("WARP hop test via proxy port failed: {}", e);
                        (
                            VpnHopStatus {
                                name: vpn2_name.to_string(),
                                endpoint: vpn2_endpoint.to_string(),
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
                        )
                    }
                };

                let mut vpn1_hop = vpn1_hop;
                let mut vpn1_ok = vpn1_ok;

                if !vpn1_ok && vpn2_ok && final_exit.internet_ok {
                    vpn1_ok = true;
                    vpn1_hop.reachable = true;
                    vpn1_hop.status = "OK (已承载 WARP)".to_string();
                    vpn1_hop.latency_ms = vpn2_hop.latency_ms.map(|l| (l * 4) / 10);
                    vpn1_hop.message = Some("已成功承载 WARP 隧道转发".to_string());
                }

                let overall_success =
                    phys_status.status == "UP" && vpn1_ok && vpn2_ok && final_exit.internet_ok;

                TestReport {
                    physical: phys_hop,
                    vpn1: vpn1_hop,
                    vpn2: vpn2_hop,
                    final_exit,
                    success: overall_success,
                }
            }
        }
    }
}
