use crate::error::{ChainError, Result};
use crate::model::config::{ChainProxyConfig, ParsedNodes, ProxyMode};
use crate::proxy::socks5::Socks5User;
use crate::singbox::generator::{TEST_VPN1_PORT, TEST_WARP_PORT};
use crate::warp_kernel::endpoint::{build_warp_candidates, resolve_endpoint_addr};
use crate::warp_kernel::noise::{DecapOutcome, WgTunnel};
use crate::warp_kernel::pkt::{
    unwrap_ipv4_udp, wrap_ipv4_udp, L3NatTable, TcpMicroProbe,
};
use crate::wireguard::model::WgConfig;
use base64::prelude::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::info;

const TUN_IPV4: Ipv4Addr = Ipv4Addr::new(172, 31, 255, 1);
const INNER_WG_SPORT: u16 = 51821;
const TCP_MSS_CLAMP: u16 = 1200;

#[derive(Debug, Clone, Default)]
pub struct KernelStats {
    pub vpn1_tx: u64,
    pub vpn1_rx: u64,
    pub warp_tx: u64,
    pub warp_rx: u64,
    pub active_warp_endpoint: Option<String>,
}

enum ProbeTarget {
    Vpn1,
    Warp,
}

struct ProbeJob {
    target: ProbeTarget,
    reply_tx: mpsc::SyncSender<std::result::Result<String, String>>,
}

struct ActiveProbe {
    target: ProbeTarget,
    fsm: TcpMicroProbe,
    started_at: Instant,
    last_tx: Instant,
    retries: u8,
    reply_tx: mpsc::SyncSender<std::result::Result<String, String>>,
}

#[derive(Clone)]
struct TunnelSpec {
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    preshared_key: [u8; 32],
    reserved: [u8; 3],
    endpoint: SocketAddr,
    candidates: Vec<SocketAddr>,
    local_v4: Ipv4Addr,
    local_v6: Option<Ipv6Addr>,
    dns_v4: Ipv4Addr,
}

impl TunnelSpec {
    fn from_wg_config(cfg: &WgConfig, is_warp: bool) -> Result<Self> {
        let priv_vec = BASE64_STANDARD
            .decode(cfg.interface.private_key.trim().as_bytes())
            .map_err(|e| ChainError::ValidationError(format!("Invalid PrivateKey base64: {}", e)))?;
        if priv_vec.len() != 32 {
            return Err(ChainError::ValidationError(
                "WireGuard PrivateKey must be 32 bytes".to_string(),
            ));
        }
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&priv_vec);

        let peer = cfg
            .peers
            .first()
            .ok_or_else(|| ChainError::ValidationError("Missing WireGuard Peer".to_string()))?;
        let pub_vec = BASE64_STANDARD
            .decode(peer.public_key.trim().as_bytes())
            .map_err(|e| ChainError::ValidationError(format!("Invalid PublicKey base64: {}", e)))?;
        if pub_vec.len() != 32 {
            return Err(ChainError::ValidationError(
                "WireGuard PublicKey must be 32 bytes".to_string(),
            ));
        }
        let mut peer_public_key = [0u8; 32];
        peer_public_key.copy_from_slice(&pub_vec);

        let mut preshared_key = [0u8; 32];
        if let Some(ref psk_str) = peer.preshared_key {
            let v = BASE64_STANDARD
                .decode(psk_str.trim().as_bytes())
                .map_err(|e| ChainError::ValidationError(format!("Invalid PSK base64: {}", e)))?;
            if v.len() == 32 {
                preshared_key.copy_from_slice(&v);
            }
        }

        let mut local_v4 = if is_warp {
            Ipv4Addr::new(172, 16, 0, 2)
        } else {
            Ipv4Addr::new(10, 2, 0, 2)
        };
        let mut local_v6 = None;
        for net in &cfg.interface.addresses {
            match net.addr() {
                IpAddr::V4(v4) => local_v4 = v4,
                IpAddr::V6(v6) => local_v6 = Some(v6),
            }
        }

        let mut dns_v4 = Ipv4Addr::new(1, 1, 1, 1);
        for d in &cfg.interface.dns {
            if let IpAddr::V4(v4) = d {
                dns_v4 = *v4;
                break;
            }
        }

        let configured_ep = if let Some(ref ep) = peer.endpoint {
            resolve_endpoint_addr(&ep.host, ep.port)
        } else {
            None
        };

        let endpoint = configured_ep.unwrap_or_else(|| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(162, 159, 192, 1)), 2408)
        });

        let candidates = if is_warp {
            build_warp_candidates(Some(endpoint))
        } else {
            vec![endpoint]
        };

        Ok(Self {
            private_key,
            peer_public_key,
            preshared_key,
            reserved: cfg.interface.reserved,
            endpoint,
            candidates,
            local_v4,
            local_v6,
            dns_v4,
        })
    }
}

pub struct WarpKernel {
    running: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    tokio_abort_handles: Vec<tokio::task::AbortHandle>,
    vpn1_tx: Arc<AtomicU64>,
    vpn1_rx: Arc<AtomicU64>,
    warp_tx: Arc<AtomicU64>,
    warp_rx: Arc<AtomicU64>,
    active_warp_ep: Arc<Mutex<Option<String>>>,
}

impl Default for WarpKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl WarpKernel {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
            tokio_abort_handles: Vec::new(),
            vpn1_tx: Arc::new(AtomicU64::new(0)),
            vpn1_rx: Arc::new(AtomicU64::new(0)),
            warp_tx: Arc::new(AtomicU64::new(0)),
            warp_rx: Arc::new(AtomicU64::new(0)),
            active_warp_ep: Arc::new(Mutex::new(None)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn stats(&self) -> KernelStats {
        KernelStats {
            vpn1_tx: self.vpn1_tx.load(Ordering::Relaxed),
            vpn1_rx: self.vpn1_rx.load(Ordering::Relaxed),
            warp_tx: self.warp_tx.load(Ordering::Relaxed),
            warp_rx: self.warp_rx.load(Ordering::Relaxed),
            active_warp_endpoint: self.active_warp_ep.lock().unwrap().clone(),
        }
    }

    /// Stop any official `warp-svc` / `cloudflare-warp` background daemon on Linux
    /// so it never wastes 150MB+ RAM or conflicts with our lightweight kernel.
    pub fn stop_official_warp_daemons() {
        #[cfg(target_os = "linux")]
        {
            if std::path::Path::new("/bin/systemctl").exists()
                || std::path::Path::new("/usr/bin/systemctl").exists()
            {
                let _ = std::process::Command::new("systemctl")
                    .args(["stop", "warp-svc"])
                    .output();
                let _ = std::process::Command::new("systemctl")
                    .args(["disable", "warp-svc"])
                    .output();
            }
            let _ = std::process::Command::new("pkill")
                .args(["-9", "-f", "warp-svc"])
                .output();
        }
    }

    /// Returns true if this mode is handled natively by the built-in Rust WarpKernel
    /// without needing any external `sing-box` binary.
    pub fn supports_mode(mode: ProxyMode) -> bool {
        matches!(
            mode,
            ProxyMode::WgChainWarp
                | ProxyMode::StandaloneWarp
                | ProxyMode::StandaloneWg
                | ProxyMode::Socks5Server
        )
    }

    pub fn start(
        &mut self,
        config: &ChainProxyConfig,
        parsed: &ParsedNodes,
        uplink: &str,
        local_ip_str: &str,
    ) -> Result<()> {
        self.stop();
        Self::stop_official_warp_daemons();

        self.vpn1_tx.store(0, Ordering::Relaxed);
        self.vpn1_rx.store(0, Ordering::Relaxed);
        self.warp_tx.store(0, Ordering::Relaxed);
        self.warp_rx.store(0, Ordering::Relaxed);
        *self.active_warp_ep.lock().unwrap() = None;

        if config.mode == ProxyMode::Socks5Server {
            let srv = config
                .socks5_server
                .as_ref()
                .ok_or_else(|| ChainError::ValidationError("Missing SOCKS5 server config".into()))?
                .clone();
            srv.validate()?;
            self.running.store(true, Ordering::SeqCst);
            let running = self.running.clone();
            let vpn1_tx = self.vpn1_tx.clone();
            let vpn1_rx = self.vpn1_rx.clone();
            let handle = tokio::spawn(async move {
                let _ = run_native_socks5_server(
                    SocketAddr::new(srv.listen, srv.port),
                    srv.users,
                    running,
                    vpn1_tx,
                    vpn1_rx,
                )
                .await;
            });
            self.tokio_abort_handles.push(handle.abort_handle());
            return Ok(());
        }

        let host_ipv4 = local_ip_str.parse::<Ipv4Addr>().unwrap_or(TUN_IPV4);

        let (vpn1_spec, warp_spec) = match config.mode {
            ProxyMode::WgChainWarp => {
                let v1 = parsed.vpn1.as_ref().ok_or_else(|| {
                    ChainError::ValidationError("Missing VPN1 WireGuard config".into())
                })?;
                let v2 = parsed.vpn2.as_ref().ok_or_else(|| {
                    ChainError::ValidationError("Missing WARP WireGuard config".into())
                })?;
                (
                    Some(TunnelSpec::from_wg_config(v1, false)?),
                    Some(TunnelSpec::from_wg_config(v2, true)?),
                )
            }
            ProxyMode::StandaloneWarp => {
                let v2 = parsed.vpn2.as_ref().ok_or_else(|| {
                    ChainError::ValidationError("Missing WARP WireGuard config".into())
                })?;
                (None, Some(TunnelSpec::from_wg_config(v2, true)?))
            }
            ProxyMode::StandaloneWg => {
                let v1 = parsed.vpn1.as_ref().ok_or_else(|| {
                    ChainError::ValidationError("Missing VPN1 WireGuard config".into())
                })?;
                (Some(TunnelSpec::from_wg_config(v1, false)?), None)
            }
            _ => {
                return Err(ChainError::ValidationError(format!(
                    "Mode {:?} not supported by native L3 WarpKernel",
                    config.mode
                )))
            }
        };

        if let Some(ref w) = warp_spec {
            *self.active_warp_ep.lock().unwrap() = Some(w.endpoint.to_string());
        }

        let tun_fd = create_and_configure_tun("chain0", config.routing.ipv6)?;
        let udp_sock = create_marked_udp_socket(uplink)?;

        let (probe_tx, probe_rx) = mpsc::sync_channel::<ProbeJob>(16);

        self.running.store(true, Ordering::SeqCst);

        if config.mode == ProxyMode::WgChainWarp {
            if let Ok(h1) = spawn_probe_http_listener(
                TEST_VPN1_PORT,
                ProbeTarget::Vpn1,
                probe_tx.clone(),
                self.running.clone(),
            ) {
                self.workers.push(h1);
            }
        }
        let main_probe_target = match config.mode {
            ProxyMode::StandaloneWg => ProbeTarget::Vpn1,
            _ => ProbeTarget::Warp,
        };
        if let Ok(h2) = spawn_probe_http_listener(
            TEST_WARP_PORT,
            main_probe_target,
            probe_tx,
            self.running.clone(),
        ) {
            self.workers.push(h2);
        }

        let running_clone = self.running.clone();
        let vpn1_tx = self.vpn1_tx.clone();
        let vpn1_rx = self.vpn1_rx.clone();
        let warp_tx = self.warp_tx.clone();
        let warp_rx = self.warp_rx.clone();
        let active_warp_ep = self.active_warp_ep.clone();
        let mode = config.mode;

        let worker = std::thread::Builder::new()
            .name("sooya-warp-kernel".to_string())
            .spawn(move || {
                run_kernel_packet_loop(
                    mode,
                    tun_fd,
                    udp_sock,
                    host_ipv4,
                    vpn1_spec,
                    warp_spec,
                    probe_rx,
                    running_clone,
                    vpn1_tx,
                    vpn1_rx,
                    warp_tx,
                    warp_rx,
                    active_warp_ep,
                );
            })
            .map_err(|e| {
                ChainError::SystemError(format!("Failed to spawn WarpKernel thread: {}", e))
            })?;

        self.workers.push(worker);
        info!(
            "Sooya native Rust WarpKernel started for mode {:?}",
            config.mode
        );
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        for abort in self.tokio_abort_handles.drain(..) {
            abort.abort();
        }
        let _ = std::net::TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], TEST_VPN1_PORT)),
            Duration::from_millis(10),
        );
        let _ = std::net::TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], TEST_WARP_PORT)),
            Duration::from_millis(10),
        );
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Drop for WarpKernel {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_probe_http_listener(
    port: u16,
    target: ProbeTarget,
    probe_tx: mpsc::SyncSender<ProbeJob>,
    running: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
        ChainError::NetworkError(format!("Failed to bind probe listener 127.0.0.1:{}: {}", port, e))
    })?;
    let _ = listener.set_nonblocking(false);

    std::thread::Builder::new()
        .name(format!("sooya-probe-{}", port))
        .spawn(move || {
            for stream_res in listener.incoming() {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(mut stream) = stream_res else {
                    continue;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));

                let mut req_buf = [0u8; 512];
                let n = stream.read(&mut req_buf).unwrap_or(0);
                if n == 0 || !running.load(Ordering::Relaxed) {
                    continue;
                }

                let tgt = match target {
                    ProbeTarget::Vpn1 => ProbeTarget::Vpn1,
                    ProbeTarget::Warp => ProbeTarget::Warp,
                };
                let (reply_tx, reply_rx) = mpsc::sync_channel(1);
                if probe_tx
                    .send(ProbeJob {
                        target: tgt,
                        reply_tx,
                    })
                    .is_err()
                {
                    break;
                }

                match reply_rx.recv_timeout(Duration::from_millis(3200)) {
                    Ok(Ok(trace_body)) => {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            trace_body.len(),
                            trace_body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    Ok(Err(err_msg)) => {
                        let resp = format!(
                            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            err_msg.len(),
                            err_msg
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    Err(_) => {
                        let msg = "Probe timeout";
                        let resp = format!(
                            "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            msg.len(),
                            msg
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                }
            }
        })
        .map_err(|e| ChainError::SystemError(e.to_string()))
}

fn extract_ipv4_udp_src(ip_pkt: &[u8]) -> Option<(Ipv4Addr, u16)> {
    if ip_pkt.len() < 28 || (ip_pkt[0] >> 4) != 4 || ip_pkt[9] != 17 {
        return None;
    }
    let ihl = ((ip_pkt[0] & 0x0f) as usize) * 4;
    if ip_pkt.len() < ihl + 8 {
        return None;
    }
    let src_ip = Ipv4Addr::new(ip_pkt[12], ip_pkt[13], ip_pkt[14], ip_pkt[15]);
    let src_port = u16::from_be_bytes([ip_pkt[ihl], ip_pkt[ihl + 1]]);
    Some((src_ip, src_port))
}

#[allow(clippy::too_many_arguments)]
fn run_kernel_packet_loop(
    mode: ProxyMode,
    tun_fd: i32,
    udp_sock: UdpSocket,
    host_ipv4: Ipv4Addr,
    vpn1_spec: Option<TunnelSpec>,
    warp_spec: Option<TunnelSpec>,
    probe_rx: mpsc::Receiver<ProbeJob>,
    running: Arc<AtomicBool>,
    vpn1_tx: Arc<AtomicU64>,
    vpn1_rx: Arc<AtomicU64>,
    warp_tx: Arc<AtomicU64>,
    warp_rx: Arc<AtomicU64>,
    active_warp_ep_shared: Arc<Mutex<Option<String>>>,
) {
    let mut vpn1_tunnel = vpn1_spec.as_ref().map(|s| {
        WgTunnel::new(
            s.private_key,
            s.peer_public_key,
            s.preshared_key,
            s.reserved,
        )
    });
    let mut warp_tunnel = warp_spec.as_ref().map(|s| {
        WgTunnel::new(
            s.private_key,
            s.peer_public_key,
            s.preshared_key,
            s.reserved,
        )
    });

    let vpn1_ep = vpn1_spec.as_ref().map(|s| s.endpoint);
    let vpn1_v4 = vpn1_spec
        .as_ref()
        .map(|s| s.local_v4)
        .unwrap_or(Ipv4Addr::new(10, 2, 0, 2));
    let vpn1_v6 = vpn1_spec.as_ref().and_then(|s| s.local_v6);
    let vpn1_dns = vpn1_spec
        .as_ref()
        .map(|s| s.dns_v4)
        .unwrap_or(Ipv4Addr::new(1, 1, 1, 1));

    let warp_candidates = warp_spec
        .as_ref()
        .map(|s| s.candidates.clone())
        .unwrap_or_default();
    let mut warp_cand_idx = 0usize;
    let mut active_warp_ep = warp_spec
        .as_ref()
        .map(|s| s.endpoint)
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(162, 159, 192, 1)), 2408));
    let warp_v4 = warp_spec
        .as_ref()
        .map(|s| s.local_v4)
        .unwrap_or(Ipv4Addr::new(172, 16, 0, 2));
    let warp_v6 = warp_spec.as_ref().and_then(|s| s.local_v6);
    let warp_dns = warp_spec
        .as_ref()
        .map(|s| s.dns_v4)
        .unwrap_or(Ipv4Addr::new(1, 1, 1, 1));

    let primary_dns = if warp_spec.is_some() {
        warp_dns
    } else {
        vpn1_dns
    };
    let mut nat_table = L3NatTable::new(host_ipv4, Some(primary_dns));
    let mut active_probes: Vec<ActiveProbe> = Vec::with_capacity(4);
    let mut next_probe_port: u16 = 42100;
    let mut ip_id_counter: u16 = 100;

    // Pre-allocated stack buffers for zero-allocation packet forwarding
    let mut tun_buf = [0u8; 2048];
    let mut udp_buf = [0u8; 2048];
    let mut wg1_buf = [0u8; 2048];
    let mut wg2_buf = [0u8; 2048];
    let mut ip_wrap_buf = [0u8; 2048];
    let mut probe_pkt_buf = [0u8; 512];

    let mut last_vpn1_hs = Instant::now() - Duration::from_secs(10);
    let mut last_warp_hs = Instant::now() - Duration::from_secs(10);

    // Helper closure to send an IP packet through vpn1 (and UDP socket)
    let send_via_vpn1 = |inner_ip: &[u8],
                         v1_tun: &mut WgTunnel,
                         v1_ep: SocketAddr,
                         sock: &UdpSocket,
                         out_buf: &mut [u8; 2048],
                         tx_counter: &AtomicU64| {
        if let Some(enc_len) = v1_tun.encapsulate(inner_ip, out_buf) {
            if sock.send_to(&out_buf[..enc_len], v1_ep).is_ok() {
                tx_counter.fetch_add(enc_len as u64, Ordering::Relaxed);
            }
        }
    };

    // Kick off initial handshakes immediately on startup
    if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
        let init = v1.format_handshake_initiation();
        let _ = udp_sock.send_to(&init, vep);
        vpn1_tx.fetch_add(148, Ordering::Relaxed);
        last_vpn1_hs = Instant::now();
    } else if let Some(ref mut w) = warp_tunnel {
        let init = w.format_handshake_initiation();
        let _ = udp_sock.send_to(&init, active_warp_ep);
        warp_tx.fetch_add(148, Ordering::Relaxed);
        last_warp_hs = Instant::now();
    }

    while running.load(Ordering::Relaxed) {
        // 1. Check handshake & keepalive state machines
        if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
            if !v1.has_session() && last_vpn1_hs.elapsed() >= Duration::from_millis(650) {
                let init = v1.format_handshake_initiation();
                let _ = udp_sock.send_to(&init, vep);
                vpn1_tx.fetch_add(148, Ordering::Relaxed);
                last_vpn1_hs = Instant::now();
            } else if v1.needs_handshake() && last_vpn1_hs.elapsed() >= Duration::from_secs(3) {
                let init = v1.format_handshake_initiation();
                let _ = udp_sock.send_to(&init, vep);
                vpn1_tx.fetch_add(148, Ordering::Relaxed);
                last_vpn1_hs = Instant::now();
            } else if v1.needs_keepalive() {
                send_via_vpn1(&[], v1, vep, &udp_sock, &mut wg1_buf, &vpn1_tx);
            }
        }

        if let Some(ref mut w) = warp_tunnel {
            let outer_ready = vpn1_tunnel.as_ref().map(|v| v.has_session()).unwrap_or(true);
            if outer_ready {
                if !w.has_session() && last_warp_hs.elapsed() >= Duration::from_millis(500) {
                    // Happy-Eyeballs: rotate through WARP Anycast candidates (2408, 500, 4500, 1701 across 162.159.x.x & 188.114.x.x)
                    if !warp_candidates.is_empty() {
                        active_warp_ep = warp_candidates[warp_cand_idx % warp_candidates.len()];
                        warp_cand_idx = warp_cand_idx.wrapping_add(1);
                    }
                    let init = w.format_handshake_initiation();
                    if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
                        let dst_v4 = match active_warp_ep.ip() {
                            IpAddr::V4(v4) => v4,
                            IpAddr::V6(_) => Ipv4Addr::new(162, 159, 192, 1),
                        };
                        ip_id_counter = ip_id_counter.wrapping_add(1);
                        let wrapped_len = wrap_ipv4_udp(
                            &init,
                            vpn1_v4,
                            INNER_WG_SPORT,
                            dst_v4,
                            active_warp_ep.port(),
                            ip_id_counter,
                            &mut ip_wrap_buf,
                        );
                        send_via_vpn1(
                            &ip_wrap_buf[..wrapped_len],
                            v1,
                            vep,
                            &udp_sock,
                            &mut wg1_buf,
                            &vpn1_tx,
                        );
                    } else {
                        let _ = udp_sock.send_to(&init, active_warp_ep);
                    }
                    warp_tx.fetch_add(148, Ordering::Relaxed);
                    last_warp_hs = Instant::now();
                } else if w.needs_handshake() && last_warp_hs.elapsed() >= Duration::from_secs(3) {
                    let init = w.format_handshake_initiation();
                    if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
                        let dst_v4 = match active_warp_ep.ip() {
                            IpAddr::V4(v4) => v4,
                            IpAddr::V6(_) => Ipv4Addr::new(162, 159, 192, 1),
                        };
                        ip_id_counter = ip_id_counter.wrapping_add(1);
                        let wrapped_len = wrap_ipv4_udp(
                            &init,
                            vpn1_v4,
                            INNER_WG_SPORT,
                            dst_v4,
                            active_warp_ep.port(),
                            ip_id_counter,
                            &mut ip_wrap_buf,
                        );
                        send_via_vpn1(
                            &ip_wrap_buf[..wrapped_len],
                            v1,
                            vep,
                            &udp_sock,
                            &mut wg1_buf,
                            &vpn1_tx,
                        );
                    } else {
                        let _ = udp_sock.send_to(&init, active_warp_ep);
                    }
                    warp_tx.fetch_add(148, Ordering::Relaxed);
                    last_warp_hs = Instant::now();
                } else if w.needs_keepalive() {
                    if let Some(w_len) = w.encapsulate_keepalive(&mut wg2_buf) {
                        warp_tx.fetch_add(w_len as u64, Ordering::Relaxed);
                        if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
                            let dst_v4 = match active_warp_ep.ip() {
                                IpAddr::V4(v4) => v4,
                                IpAddr::V6(_) => Ipv4Addr::new(162, 159, 192, 1),
                            };
                            ip_id_counter = ip_id_counter.wrapping_add(1);
                            let wrapped_len = wrap_ipv4_udp(
                                &wg2_buf[..w_len],
                                vpn1_v4,
                                INNER_WG_SPORT,
                                dst_v4,
                                active_warp_ep.port(),
                                ip_id_counter,
                                &mut ip_wrap_buf,
                            );
                            send_via_vpn1(
                                &ip_wrap_buf[..wrapped_len],
                                v1,
                                vep,
                                &udp_sock,
                                &mut wg1_buf,
                                &vpn1_tx,
                            );
                        } else {
                            let _ = udp_sock.send_to(&wg2_buf[..w_len], active_warp_ep);
                        }
                    }
                }
            }
        }

        // 2. Accept new probe jobs from local HTTP probe listeners
        while let Ok(job) = probe_rx.try_recv() {
            next_probe_port = if next_probe_port >= 60000 {
                42100
            } else {
                next_probe_port + 1
            };
            let local_ip = match job.target {
                ProbeTarget::Vpn1 => vpn1_v4,
                ProbeTarget::Warp => warp_v4,
            };
            let fsm = TcpMicroProbe::new(local_ip, next_probe_port, Ipv4Addr::new(1, 1, 1, 1));
            active_probes.push(ActiveProbe {
                target: job.target,
                fsm,
                started_at: Instant::now(),
                last_tx: Instant::now() - Duration::from_secs(1),
                retries: 0,
                reply_tx: job.reply_tx,
            });
        }

        // 3. Drive active L3 TcpMicroProbes
        let mut idx = 0;
        while idx < active_probes.len() {
            if active_probes[idx].started_at.elapsed() > Duration::from_millis(3000) {
                let p = active_probes.swap_remove(idx);
                let _ = p.reply_tx.send(Err("Probe timed out".to_string()));
                continue;
            }

            let can_send = match active_probes[idx].target {
                ProbeTarget::Vpn1 => vpn1_tunnel.as_ref().map(|v| v.has_session()).unwrap_or(false),
                ProbeTarget::Warp => warp_tunnel.as_ref().map(|w| w.has_session()).unwrap_or(false),
            };

            if can_send
                && !active_probes[idx].fsm.request_sent
                && active_probes[idx].last_tx.elapsed() >= Duration::from_millis(350)
                && active_probes[idx].retries < 5
            {
                let n = active_probes[idx].fsm.build_syn(&mut probe_pkt_buf);
                active_probes[idx].last_tx = Instant::now();
                active_probes[idx].retries += 1;
                match active_probes[idx].target {
                    ProbeTarget::Vpn1 => {
                        if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
                            send_via_vpn1(
                                &probe_pkt_buf[..n],
                                v1,
                                vep,
                                &udp_sock,
                                &mut wg1_buf,
                                &vpn1_tx,
                            );
                        }
                    }
                    ProbeTarget::Warp => {
                        if let Some(ref mut w) = warp_tunnel {
                            if let Some(w_len) = w.encapsulate(&probe_pkt_buf[..n], &mut wg2_buf) {
                                warp_tx.fetch_add(w_len as u64, Ordering::Relaxed);
                                if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
                                    let dst_v4 = match active_warp_ep.ip() {
                                        IpAddr::V4(v4) => v4,
                                        IpAddr::V6(_) => Ipv4Addr::new(162, 159, 192, 1),
                                    };
                                    ip_id_counter = ip_id_counter.wrapping_add(1);
                                    let wrapped_len = wrap_ipv4_udp(
                                        &wg2_buf[..w_len],
                                        vpn1_v4,
                                        INNER_WG_SPORT,
                                        dst_v4,
                                        active_warp_ep.port(),
                                        ip_id_counter,
                                        &mut ip_wrap_buf,
                                    );
                                    send_via_vpn1(
                                        &ip_wrap_buf[..wrapped_len],
                                        v1,
                                        vep,
                                        &udp_sock,
                                        &mut wg1_buf,
                                        &vpn1_tx,
                                    );
                                } else {
                                    let _ = udp_sock.send_to(&wg2_buf[..w_len], active_warp_ep);
                                }
                            }
                        }
                    }
                }
            }
            idx += 1;
        }

        // 4. Wait for I/O readiness on TUN fd or UDP socket fd via poll()
        let both_ready = match mode {
            ProxyMode::WgChainWarp => {
                vpn1_tunnel.as_ref().map(|v| v.has_session()).unwrap_or(false)
                    && warp_tunnel.as_ref().map(|w| w.has_session()).unwrap_or(false)
            }
            ProxyMode::StandaloneWarp => {
                warp_tunnel.as_ref().map(|w| w.has_session()).unwrap_or(false)
            }
            ProxyMode::StandaloneWg => {
                vpn1_tunnel.as_ref().map(|v| v.has_session()).unwrap_or(false)
            }
            _ => true,
        };
        let poll_timeout_ms = if !both_ready || !active_probes.is_empty() {
            25
        } else {
            250
        };
        poll_fds(tun_fd, &udp_sock, poll_timeout_ms);

        // 5. Drain inbound packets from physical UDP socket
        for _ in 0..64 {
            let Ok((udp_len, src_addr)) = udp_sock.recv_from(&mut udp_buf) else {
                break;
            };
            if udp_len < 4 {
                continue;
            }

            if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
                // Outer tunnel is VPN1 (StandaloneWg or WgChainWarp)
                vpn1_rx.fetch_add(udp_len as u64, Ordering::Relaxed);
                match v1.decapsulate(&udp_buf[..udp_len], &mut wg1_buf) {
                    DecapOutcome::None | DecapOutcome::Keepalive => {}
                    DecapOutcome::HandshakeCompleted { .. } => {
                        info!("VPN1 WireGuard handshake established with {}", src_addr);
                        // Send immediate keepalive to confirm session
                        if let Some(ka_len) = v1.encapsulate_keepalive(&mut tun_buf) {
                            let _ = udp_sock.send_to(&tun_buf[..ka_len], vep);
                            vpn1_tx.fetch_add(ka_len as u64, Ordering::Relaxed);
                        }

                        // If WgChainWarp, immediately fire inner WARP handshake over VPN1!
                        if let Some(ref mut w) = warp_tunnel {
                            if !w.has_session() {
                                let init = w.format_handshake_initiation();
                                let dst_v4 = match active_warp_ep.ip() {
                                    IpAddr::V4(v4) => v4,
                                    IpAddr::V6(_) => Ipv4Addr::new(162, 159, 192, 1),
                                };
                                ip_id_counter = ip_id_counter.wrapping_add(1);
                                let wrapped_len = wrap_ipv4_udp(
                                    &init,
                                    vpn1_v4,
                                    INNER_WG_SPORT,
                                    dst_v4,
                                    active_warp_ep.port(),
                                    ip_id_counter,
                                    &mut ip_wrap_buf,
                                );
                                send_via_vpn1(
                                    &ip_wrap_buf[..wrapped_len],
                                    v1,
                                    vep,
                                    &udp_sock,
                                    &mut tun_buf,
                                    &vpn1_tx,
                                );
                                warp_tx.fetch_add(148, Ordering::Relaxed);
                                last_warp_hs = Instant::now();
                            }
                        }
                    }
                    DecapOutcome::IpPacket(inner_pkt) => {
                        let inner_len = inner_pkt.len();
                        // Copy inner_pkt length so we can mutate or inspect wg1_buf[..inner_len]
                        let mut consumed_by_probe = false;
                        let mut p_idx = 0;
                        while p_idx < active_probes.len() {
                            if matches!(active_probes[p_idx].target, ProbeTarget::Vpn1) {
                                let (tx_len, body_opt) = active_probes[p_idx]
                                    .fsm
                                    .on_packet(&wg1_buf[..inner_len], &mut probe_pkt_buf);
                                if tx_len > 0 || body_opt.is_some() {
                                    consumed_by_probe = true;
                                    if tx_len > 0 {
                                        send_via_vpn1(
                                            &probe_pkt_buf[..tx_len],
                                            v1,
                                            vep,
                                            &udp_sock,
                                            &mut wg2_buf,
                                            &vpn1_tx,
                                        );
                                    }
                                    if let Some(body) = body_opt {
                                        let p = active_probes.swap_remove(p_idx);
                                        let _ = p.reply_tx.send(Ok(body));
                                        break;
                                    }
                                }
                            }
                            p_idx += 1;
                        }
                        if consumed_by_probe {
                            continue;
                        }

                        if let Some(ref mut w) = warp_tunnel {
                            // Mode is WgChainWarp: unwrap inner UDP packet addressed to INNER_WG_SPORT
                            if let (Some((src_ip, src_port)), Some(inner_udp)) = (
                                extract_ipv4_udp_src(&wg1_buf[..inner_len]),
                                unwrap_ipv4_udp(&wg1_buf[..inner_len], INNER_WG_SPORT),
                            ) {
                                warp_rx.fetch_add(inner_udp.len() as u64, Ordering::Relaxed);
                                match w.decapsulate(inner_udp, &mut wg2_buf) {
                                    DecapOutcome::None | DecapOutcome::Keepalive => {}
                                    DecapOutcome::HandshakeCompleted { .. } => {
                                        active_warp_ep =
                                            SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));
                                        *active_warp_ep_shared.lock().unwrap() =
                                            Some(active_warp_ep.to_string());
                                        info!(
                                            "WARP inner tunnel handshake established over VPN1 via {}",
                                            active_warp_ep
                                        );
                                        if let Some(ka_len) = w.encapsulate_keepalive(&mut tun_buf)
                                        {
                                            ip_id_counter = ip_id_counter.wrapping_add(1);
                                            let wrapped_len = wrap_ipv4_udp(
                                                &tun_buf[..ka_len],
                                                vpn1_v4,
                                                INNER_WG_SPORT,
                                                src_ip,
                                                src_port,
                                                ip_id_counter,
                                                &mut ip_wrap_buf,
                                            );
                                            send_via_vpn1(
                                                &ip_wrap_buf[..wrapped_len],
                                                v1,
                                                vep,
                                                &udp_sock,
                                                &mut tun_buf,
                                                &vpn1_tx,
                                            );
                                        }
                                    }
                                    DecapOutcome::IpPacket(app_pkt) => {
                                        let app_len = app_pkt.len();
                                        let mut warp_probe_hit = false;
                                        let mut wp_idx = 0;
                                        while wp_idx < active_probes.len() {
                                            if matches!(
                                                active_probes[wp_idx].target,
                                                ProbeTarget::Warp
                                            ) {
                                                let (tx_len, body_opt) = active_probes[wp_idx]
                                                    .fsm
                                                    .on_packet(
                                                        &wg2_buf[..app_len],
                                                        &mut probe_pkt_buf,
                                                    );
                                                if tx_len > 0 || body_opt.is_some() {
                                                    warp_probe_hit = true;
                                                    if tx_len > 0 {
                                                        if let Some(w_enc) = w.encapsulate(
                                                            &probe_pkt_buf[..tx_len],
                                                            &mut tun_buf,
                                                        ) {
                                                            warp_tx.fetch_add(
                                                                w_enc as u64,
                                                                Ordering::Relaxed,
                                                            );
                                                            ip_id_counter =
                                                                ip_id_counter.wrapping_add(1);
                                                            let wrapped_len = wrap_ipv4_udp(
                                                                &tun_buf[..w_enc],
                                                                vpn1_v4,
                                                                INNER_WG_SPORT,
                                                                src_ip,
                                                                src_port,
                                                                ip_id_counter,
                                                                &mut ip_wrap_buf,
                                                            );
                                                            send_via_vpn1(
                                                                &ip_wrap_buf[..wrapped_len],
                                                                v1,
                                                                vep,
                                                                &udp_sock,
                                                                &mut tun_buf,
                                                                &vpn1_tx,
                                                            );
                                                        }
                                                    }
                                                    if let Some(body) = body_opt {
                                                        let p = active_probes.swap_remove(wp_idx);
                                                        let _ = p.reply_tx.send(Ok(body));
                                                        break;
                                                    }
                                                }
                                            }
                                            wp_idx += 1;
                                        }
                                        if warp_probe_hit {
                                            continue;
                                        }

                                        let pkt_slice = &mut wg2_buf[..app_len];
                                        if nat_table.translate_inbound(pkt_slice, TCP_MSS_CLAMP) {
                                            write_tun(tun_fd, pkt_slice);
                                        }
                                    }
                                }
                            }
                        } else {
                            // StandaloneWg: deliver decrypted VPN1 packet to chain0 TUN
                            let pkt_slice = &mut wg1_buf[..inner_len];
                            if nat_table.translate_inbound(pkt_slice, TCP_MSS_CLAMP) {
                                write_tun(tun_fd, pkt_slice);
                            }
                        }
                    }
                }
            } else if let Some(ref mut w) = warp_tunnel {
                // StandaloneWarp: outer UDP socket talks directly to WARP
                warp_rx.fetch_add(udp_len as u64, Ordering::Relaxed);
                match w.decapsulate(&udp_buf[..udp_len], &mut wg2_buf) {
                    DecapOutcome::None | DecapOutcome::Keepalive => {}
                    DecapOutcome::HandshakeCompleted { .. } => {
                        active_warp_ep = src_addr;
                        *active_warp_ep_shared.lock().unwrap() = Some(active_warp_ep.to_string());
                        info!(
                            "Standalone WARP handshake established via {}",
                            active_warp_ep
                        );
                        if let Some(ka_len) = w.encapsulate_keepalive(&mut wg1_buf) {
                            let _ = udp_sock.send_to(&wg1_buf[..ka_len], active_warp_ep);
                            warp_tx.fetch_add(ka_len as u64, Ordering::Relaxed);
                        }
                    }
                    DecapOutcome::IpPacket(app_pkt) => {
                        let app_len = app_pkt.len();
                        let mut warp_probe_hit = false;
                        let mut wp_idx = 0;
                        while wp_idx < active_probes.len() {
                            if matches!(active_probes[wp_idx].target, ProbeTarget::Warp) {
                                let (tx_len, body_opt) = active_probes[wp_idx]
                                    .fsm
                                    .on_packet(&wg2_buf[..app_len], &mut probe_pkt_buf);
                                if tx_len > 0 || body_opt.is_some() {
                                    warp_probe_hit = true;
                                    if tx_len > 0 {
                                        if let Some(w_enc) =
                                            w.encapsulate(&probe_pkt_buf[..tx_len], &mut wg1_buf)
                                        {
                                            let _ =
                                                udp_sock.send_to(&wg1_buf[..w_enc], active_warp_ep);
                                            warp_tx.fetch_add(w_enc as u64, Ordering::Relaxed);
                                        }
                                    }
                                    if let Some(body) = body_opt {
                                        let p = active_probes.swap_remove(wp_idx);
                                        let _ = p.reply_tx.send(Ok(body));
                                        break;
                                    }
                                }
                            }
                            wp_idx += 1;
                        }
                        if warp_probe_hit {
                            continue;
                        }

                        let pkt_slice = &mut wg2_buf[..app_len];
                        if nat_table.translate_inbound(pkt_slice, TCP_MSS_CLAMP) {
                            write_tun(tun_fd, pkt_slice);
                        }
                    }
                }
            }
        }

        // 6. Drain outbound IP packets from chain0 TUN
        for _ in 0..64 {
            let Some(pkt_len) = read_tun(tun_fd, &mut tun_buf) else {
                break;
            };
            if pkt_len < 20 {
                continue;
            }
            let pkt_slice = &mut tun_buf[..pkt_len];

            if let Some(ref mut w) = warp_tunnel {
                if !nat_table.translate_outbound(pkt_slice, warp_v4, warp_v6, TCP_MSS_CLAMP) {
                    continue;
                }
                if let Some(w_len) = w.encapsulate(pkt_slice, &mut wg2_buf) {
                    warp_tx.fetch_add(w_len as u64, Ordering::Relaxed);
                    if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
                        let dst_v4 = match active_warp_ep.ip() {
                            IpAddr::V4(v4) => v4,
                            IpAddr::V6(_) => Ipv4Addr::new(162, 159, 192, 1),
                        };
                        ip_id_counter = ip_id_counter.wrapping_add(1);
                        let wrapped_len = wrap_ipv4_udp(
                            &wg2_buf[..w_len],
                            vpn1_v4,
                            INNER_WG_SPORT,
                            dst_v4,
                            active_warp_ep.port(),
                            ip_id_counter,
                            &mut ip_wrap_buf,
                        );
                        send_via_vpn1(
                            &ip_wrap_buf[..wrapped_len],
                            v1,
                            vep,
                            &udp_sock,
                            &mut wg1_buf,
                            &vpn1_tx,
                        );
                    } else {
                        let _ = udp_sock.send_to(&wg2_buf[..w_len], active_warp_ep);
                    }
                }
            } else if let (Some(ref mut v1), Some(vep)) = (&mut vpn1_tunnel, vpn1_ep) {
                if !nat_table.translate_outbound(pkt_slice, vpn1_v4, vpn1_v6, TCP_MSS_CLAMP) {
                    continue;
                }
                send_via_vpn1(pkt_slice, v1, vep, &udp_sock, &mut wg1_buf, &vpn1_tx);
            }
        }
    }

    close_tun(tun_fd);
    info!("Sooya native Rust WarpKernel stopped cleanly");
}

/// Native async Rust SOCKS5 Server (RFC 1928 + RFC 1929 Username/Password Auth)
async fn run_native_socks5_server(
    listen_addr: SocketAddr,
    users: Vec<Socks5User>,
    running: Arc<AtomicBool>,
    tx_counter: Arc<AtomicU64>,
    rx_counter: Arc<AtomicU64>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener as TokioListener, TcpStream as TokioStream};

    let listener = TokioListener::bind(listen_addr)
        .await
        .map_err(|e| ChainError::NetworkError(format!("SOCKS5 bind failed: {}", e)))?;
    let users = Arc::new(users);

    while running.load(Ordering::Relaxed) {
        let Ok((mut client, _)) = listener.accept().await else {
            break;
        };
        let users = users.clone();
        let tx_c = tx_counter.clone();
        let rx_c = rx_counter.clone();

        tokio::spawn(async move {
            let _ = client.set_nodelay(true);
            let mut buf = [0u8; 512];
            if client.read_exact(&mut buf[..2]).await.is_err() || buf[0] != 0x05 {
                return;
            }
            let nmethods = buf[1] as usize;
            if client.read_exact(&mut buf[..nmethods]).await.is_err() {
                return;
            }
            if !buf[..nmethods].contains(&0x02) {
                let _ = client.write_all(&[0x05, 0xFF]).await;
                return;
            }
            if client.write_all(&[0x05, 0x02]).await.is_err() {
                return;
            }

            // RFC 1929 username/password auth
            if client.read_exact(&mut buf[..2]).await.is_err() || buf[0] != 0x01 {
                return;
            }
            let ulen = buf[1] as usize;
            if client.read_exact(&mut buf[..ulen + 1]).await.is_err() {
                return;
            }
            let uname = String::from_utf8_lossy(&buf[..ulen]).into_owned();
            let plen = buf[ulen] as usize;
            if client.read_exact(&mut buf[..plen]).await.is_err() {
                return;
            }
            let upass = String::from_utf8_lossy(&buf[..plen]).into_owned();

            let auth_ok = users
                .iter()
                .any(|u| u.username == uname && u.password == upass);
            if !auth_ok {
                let _ = client.write_all(&[0x01, 0x01]).await;
                return;
            }
            if client.write_all(&[0x01, 0x00]).await.is_err() {
                return;
            }

            // Read CONNECT request
            if client.read_exact(&mut buf[..4]).await.is_err() || buf[0] != 0x05 || buf[1] != 0x01
            {
                let _ = client
                    .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return;
            }
            let atyp = buf[3];
            let target_host = match atyp {
                0x01 => {
                    if client.read_exact(&mut buf[..6]).await.is_err() {
                        return;
                    }
                    let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                    let port = u16::from_be_bytes([buf[4], buf[5]]);
                    format!("{}:{}", ip, port)
                }
                0x03 => {
                    if client.read_exact(&mut buf[..1]).await.is_err() {
                        return;
                    }
                    let dlen = buf[0] as usize;
                    if client.read_exact(&mut buf[..dlen + 2]).await.is_err() {
                        return;
                    }
                    let dom = String::from_utf8_lossy(&buf[..dlen]);
                    let port = u16::from_be_bytes([buf[dlen], buf[dlen + 1]]);
                    format!("{}:{}", dom, port)
                }
                0x04 => {
                    if client.read_exact(&mut buf[..18]).await.is_err() {
                        return;
                    }
                    let mut segs = [0u8; 16];
                    segs.copy_from_slice(&buf[..16]);
                    let ip = Ipv6Addr::from(segs);
                    let port = u16::from_be_bytes([buf[16], buf[17]]);
                    format!("[{}]:{}", ip, port)
                }
                _ => return,
            };

            match TokioStream::connect(&target_host).await {
                Ok(mut upstream) => {
                    let _ = upstream.set_nodelay(true);
                    if client
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if let Ok((up, down)) =
                        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                    {
                        tx_c.fetch_add(up, Ordering::Relaxed);
                        rx_c.fetch_add(down, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    let _ = client
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                }
            }
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_and_configure_tun(name: &str, enable_ipv6: bool) -> Result<i32> {
    use crate::network::iproute::IpRouteManager;
    use std::ffi::CString;

    IpRouteManager::ensure_tun_device()?;
    let c_path = CString::new("/dev/net/tun").unwrap();
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd < 0 {
        return Err(ChainError::NetworkError(format!(
            "Failed to open /dev/net/tun: {}",
            std::io::Error::last_os_error()
        )));
    }

    #[repr(C)]
    struct IfReq {
        ifr_name: [u8; 16],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }

    let mut ifr = IfReq {
        ifr_name: [0u8; 16],
        ifr_flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
        _pad: [0u8; 22],
    };
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(15);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    let res = unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr) };
    if res < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(ChainError::NetworkError(format!(
            "ioctl(TUNSETIFF, {}) failed: {}",
            name, err
        )));
    }

    let mut batch = vec![
        format!("addr add {}/30 dev {}", TUN_IPV4, name),
        format!("link set dev {} mtu 1280 up", name),
    ];
    if enable_ipv6 {
        batch.insert(1, format!("addr add fdfe:dcba:9876::1/126 dev {}", name));
    }
    if let Err(e) = IpRouteManager::run_batch(&batch) {
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    Ok(fd)
}

#[cfg(not(target_os = "linux"))]
fn create_and_configure_tun(_name: &str, _enable_ipv6: bool) -> Result<i32> {
    Ok(-1)
}

#[cfg(target_os = "linux")]
fn create_marked_udp_socket(uplink: &str) -> Result<UdpSocket> {
    use crate::network::iproute::MARK_PHYSICAL_DIRECT;
    use std::ffi::CString;
    use std::os::unix::io::AsRawFd;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| ChainError::NetworkError(format!("UDP bind failed: {}", e)))?;
    let _ = sock.set_nonblocking(true);

    let fd = sock.as_raw_fd();
    let mark: u32 = MARK_PHYSICAL_DIRECT;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );

        if !uplink.is_empty() {
            if let Ok(c_iface) = CString::new(uplink) {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    c_iface.as_ptr() as *const libc::c_void,
                    (uplink.len() + 1) as libc::socklen_t,
                );
            }
        }

        let buf_sz: libc::c_int = 2 * 1024 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buf_sz as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &buf_sz as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    Ok(sock)
}

#[cfg(not(target_os = "linux"))]
fn create_marked_udp_socket(_uplink: &str) -> Result<UdpSocket> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| ChainError::NetworkError(format!("UDP bind failed: {}", e)))?;
    let _ = sock.set_nonblocking(true);
    Ok(sock)
}

#[cfg(target_os = "linux")]
fn poll_fds(tun_fd: i32, udp_sock: &UdpSocket, timeout_ms: i32) {
    use std::os::unix::io::AsRawFd;
    let mut fds = [
        libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: udp_sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    unsafe {
        libc::poll(fds.as_mut_ptr(), 2, timeout_ms);
    }
}

#[cfg(not(target_os = "linux"))]
fn poll_fds(_tun_fd: i32, _udp_sock: &UdpSocket, timeout_ms: i32) {
    std::thread::sleep(Duration::from_millis(timeout_ms.max(1) as u64));
}

#[cfg(target_os = "linux")]
fn read_tun(tun_fd: i32, buf: &mut [u8]) -> Option<usize> {
    if tun_fd < 0 {
        return None;
    }
    let n = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n > 0 {
        Some(n as usize)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn read_tun(_tun_fd: i32, _buf: &mut [u8]) -> Option<usize> {
    None
}

#[cfg(target_os = "linux")]
fn write_tun(tun_fd: i32, buf: &[u8]) {
    if tun_fd >= 0 && !buf.is_empty() {
        unsafe {
            let _ = libc::write(tun_fd, buf.as_ptr() as *const libc::c_void, buf.len());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn write_tun(_tun_fd: i32, _buf: &[u8]) {}

#[cfg(target_os = "linux")]
fn close_tun(tun_fd: i32) {
    if tun_fd >= 0 {
        unsafe {
            libc::close(tun_fd);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn close_tun(_tun_fd: i32) {}
