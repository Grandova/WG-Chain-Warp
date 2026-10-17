use crate::error::{ChainError, Result};
use crate::model::config::{ChainProxyConfig, ParsedNodes, ProxyMode, Socks5Config, Socks5ServerConfig, Socks5User};
use crate::warp_kernel::endpoint::{build_warp_candidates, resolve_endpoint_addr};
use crate::warp_kernel::noise::{DecapOutcome, WgTunnel};
use crate::warp_kernel::pkt::{
    encode_dns_a_query, parse_dns_a_response, unwrap_ipv4_udp, wrap_ipv4_udp, L3NatTable,
    TcpMicroProbe,
};
use crate::warp_kernel::{TEST_VPN1_PORT, TEST_WARP_PORT};
use crate::wireguard::model::WgConfig;
use base64::prelude::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::info;

const TUN_IPV4: Ipv4Addr = Ipv4Addr::new(172, 31, 255, 1);
const INNER_WG_SPORT: u16 = 51821;
const TCP_MSS_CLAMP: u16 = 1120;

#[derive(Debug, Clone, Default)]
pub struct KernelStats {
    pub vpn1_tx: u64,
    pub vpn1_rx: u64,
    pub warp_tx: u64,
    pub warp_rx: u64,
    pub vpn1_handshake_ok: bool,
    pub warp_handshake_ok: bool,
    pub active_warp_endpoint: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
        let decode32 = |s: &str, name: &str| -> Result<[u8; 32]> {
            let v = BASE64_STANDARD
                .decode(s.trim().as_bytes())
                .map_err(|e| ChainError::ValidationError(format!("Invalid {} base64: {}", name, e)))?;
            v.try_into().map_err(|_| ChainError::ValidationError(format!("{} must be 32 bytes", name)))
        };
        let private_key = decode32(&cfg.interface.private_key, "PrivateKey")?;
        let peer = cfg.peers.first().ok_or_else(|| ChainError::ValidationError("Missing Peer".into()))?;
        let peer_public_key = decode32(&peer.public_key, "PublicKey")?;
        let preshared_key = match &peer.preshared_key {
            Some(psk) if !psk.trim().is_empty() => decode32(psk, "PresharedKey")?,
            _ => [0u8; 32],
        };
        let mut local_v4 = if is_warp { Ipv4Addr::new(172, 16, 0, 2) } else { Ipv4Addr::new(10, 2, 0, 2) };
        let mut local_v6 = None;
        for net in &cfg.interface.addresses {
            match net.addr() {
                IpAddr::V4(v4) => local_v4 = v4,
                IpAddr::V6(v6) => local_v6 = Some(v6),
            }
        }
        let dns_v4 = cfg
            .interface
            .dns
            .iter()
            .filter_map(|d| match d { IpAddr::V4(v4) => Some(*v4), _ => None })
            .find(|v4| is_warp || *v4 != Ipv4Addr::new(1, 1, 1, 1))
            .unwrap_or(if is_warp { Ipv4Addr::new(1, 1, 1, 1) } else { Ipv4Addr::new(8, 8, 8, 8) });
        let endpoint = peer
            .endpoint
            .as_ref()
            .and_then(|ep| resolve_endpoint_addr(&ep.host, ep.port))
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(162, 159, 192, 1)), 2408));
        let candidates = if is_warp { build_warp_candidates(Some(endpoint)) } else { vec![endpoint] };
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

pub struct Socks5Service {
    running: Arc<AtomicBool>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    abort_handle: Option<tokio::task::AbortHandle>,
    listen_addr: Option<SocketAddr>,
    current_cfg: Option<Socks5ServerConfig>,
    tx_bytes: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
}

impl Default for Socks5Service {
    fn default() -> Self {
        Self::new()
    }
}

impl Socks5Service {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx: None,
            abort_handle: None,
            listen_addr: None,
            current_cfg: None,
            tx_bytes: Arc::new(AtomicU64::new(0)),
            rx_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn listen_addr(&self) -> Option<String> {
        if self.is_running() {
            self.listen_addr.map(|a| a.to_string())
        } else {
            None
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.tx_bytes.load(Ordering::Relaxed), self.rx_bytes.load(Ordering::Relaxed))
    }

    pub fn start(&mut self, srv: &Socks5ServerConfig, tunnel_running: Arc<AtomicBool>) -> Result<()> {
        srv.validate()?;
        if self.is_running() && self.current_cfg.as_ref() == Some(srv) {
            return Ok(());
        }
        self.stop();
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);

        let listen_addr = SocketAddr::new(srv.listen, srv.port);
        let std_listener = bind_reusable_tcp_listener(listen_addr)?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| ChainError::NetworkError(format!("SOCKS5 set_nonblocking failed: {}", e)))?;
        let tokio_listener = tokio::net::TcpListener::from_std(std_listener)
            .map_err(|e| ChainError::NetworkError(format!("SOCKS5 tokio listener failed: {}", e)))?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.running.store(true, Ordering::SeqCst);
        let (running, tx, rx) = (self.running.clone(), self.tx_bytes.clone(), self.rx_bytes.clone());
        let users = srv.users.clone();
        let h = tokio::spawn(async move {
            let _ = run_native_socks5_server(
                tokio_listener,
                users,
                running,
                tunnel_running,
                shutdown_rx,
                tx,
                rx,
            )
            .await;
        });
        self.shutdown_tx = Some(shutdown_tx);
        self.abort_handle = Some(h.abort_handle());
        self.listen_addr = Some(listen_addr);
        self.current_cfg = Some(srv.clone());
        info!("Sooya native SOCKS5 server listening on {}", listen_addr);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(abort) = self.abort_handle.take() {
            abort.abort();
        }
        self.listen_addr = None;
        self.current_cfg = None;
    }
}

impl Drop for Socks5Service {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct WarpKernel {
    running: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    probe_ports: Vec<u16>,
    vpn1_tx: Arc<AtomicU64>,
    vpn1_rx: Arc<AtomicU64>,
    warp_tx: Arc<AtomicU64>,
    warp_rx: Arc<AtomicU64>,
    vpn1_hs_ok: Arc<AtomicBool>,
    warp_hs_ok: Arc<AtomicBool>,
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
            probe_ports: Vec::new(),
            vpn1_tx: Arc::new(AtomicU64::new(0)),
            vpn1_rx: Arc::new(AtomicU64::new(0)),
            warp_tx: Arc::new(AtomicU64::new(0)),
            warp_rx: Arc::new(AtomicU64::new(0)),
            vpn1_hs_ok: Arc::new(AtomicBool::new(false)),
            warp_hs_ok: Arc::new(AtomicBool::new(false)),
            active_warp_ep: Arc::new(Mutex::new(None)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    pub fn stats(&self) -> KernelStats {
        KernelStats {
            vpn1_tx: self.vpn1_tx.load(Ordering::Relaxed),
            vpn1_rx: self.vpn1_rx.load(Ordering::Relaxed),
            warp_tx: self.warp_tx.load(Ordering::Relaxed),
            warp_rx: self.warp_rx.load(Ordering::Relaxed),
            vpn1_handshake_ok: self.vpn1_hs_ok.load(Ordering::Relaxed),
            warp_handshake_ok: self.warp_hs_ok.load(Ordering::Relaxed),
            active_warp_endpoint: self.active_warp_ep.lock().unwrap().clone(),
        }
    }

    pub fn stop_official_warp_daemons() {
        #[cfg(target_os = "linux")]
        {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                let _ = std::thread::spawn(|| {
                    let _ = std::process::Command::new("pkill").args(["-9", "-f", "warp-svc"]).output();
                    for cmd in [["stop", "warp-svc"], ["disable", "warp-svc"]] {
                        let _ = std::process::Command::new("systemctl").args(cmd).output();
                    }
                });
            });
        }
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
        for c in [&self.vpn1_tx, &self.vpn1_rx, &self.warp_tx, &self.warp_rx] {
            c.store(0, Ordering::Relaxed);
        }
        self.vpn1_hs_ok.store(false, Ordering::Relaxed);
        self.warp_hs_ok.store(false, Ordering::Relaxed);
        *self.active_warp_ep.lock().unwrap() = None;

        if config.mode == ProxyMode::Socks5Server {
            self.running.store(true, Ordering::SeqCst);
            self.vpn1_hs_ok.store(true, Ordering::Relaxed);
            return Ok(());
        }

        let host_ipv4 = local_ip_str.parse::<Ipv4Addr>().unwrap_or(TUN_IPV4);
        let (vpn1_spec, warp_spec, socks_cfg) = match config.mode {
            ProxyMode::WgChainWarp => (
                Some(TunnelSpec::from_wg_config(parsed.vpn1.as_ref().unwrap(), false)?),
                Some(TunnelSpec::from_wg_config(parsed.vpn2.as_ref().unwrap(), true)?),
                None,
            ),
            ProxyMode::SocksChainWarp => (
                None,
                Some(TunnelSpec::from_wg_config(parsed.vpn2.as_ref().unwrap(), true)?),
                parsed.socks5.clone(),
            ),
            ProxyMode::StandaloneWarp => (
                None,
                Some(TunnelSpec::from_wg_config(parsed.vpn2.as_ref().unwrap(), true)?),
                None,
            ),
            ProxyMode::StandaloneWg => (
                Some(TunnelSpec::from_wg_config(parsed.vpn1.as_ref().unwrap(), false)?),
                None,
                None,
            ),
            ProxyMode::StandaloneSocks => {
                return Err(ChainError::ValidationError(
                    "请使用『SOCKS5 -> WARP 链式模式』或『WireGuard 出站』模式".into(),
                ));
            }
            ProxyMode::Socks5Server => unreachable!(),
        };

        if let Some(ref w) = warp_spec {
            *self.active_warp_ep.lock().unwrap() = Some(w.endpoint.to_string());
        }

        // Chained modes add 60 bytes of inner WireGuard + IPv4/UDP framing before outer WG encryption;
        // setting chain0 MTU to 1200 ensures inner WARP packets never exceed a 1280-MTU VPN1 peer.
        let tun_mtu: u16 = match config.mode {
            ProxyMode::WgChainWarp | ProxyMode::SocksChainWarp => 1200,
            _ => 1280,
        };
        let tun_fd = create_and_configure_tun("chain0", config.routing.ipv6, tun_mtu)?;
        let udp_sock = create_marked_udp_socket(uplink)?;
        let (probe_tx, probe_rx) = mpsc::sync_channel::<ProbeJob>(16);
        self.running.store(true, Ordering::SeqCst);

        if config.mode == ProxyMode::WgChainWarp {
            if let Ok(h1) = spawn_probe_http_listener(TEST_VPN1_PORT, ProbeTarget::Vpn1, probe_tx.clone(), self.running.clone()) {
                self.probe_ports.push(TEST_VPN1_PORT);
                self.workers.push(h1);
            }
        }
        let main_target = if config.mode == ProxyMode::StandaloneWg { ProbeTarget::Vpn1 } else { ProbeTarget::Warp };
        if let Ok(h2) = spawn_probe_http_listener(TEST_WARP_PORT, main_target, probe_tx, self.running.clone()) {
            self.probe_ports.push(TEST_WARP_PORT);
            self.workers.push(h2);
        }

        let (running, v1_tx, v1_rx, w_tx, w_rx, v1_hs, w_hs, w_ep) = (
            self.running.clone(),
            self.vpn1_tx.clone(),
            self.vpn1_rx.clone(),
            self.warp_tx.clone(),
            self.warp_rx.clone(),
            self.vpn1_hs_ok.clone(),
            self.warp_hs_ok.clone(),
            self.active_warp_ep.clone(),
        );
        let uplink_str = uplink.to_string();
        let worker = std::thread::Builder::new()
            .name("sooya-warp-kernel".into())
            .spawn(move || {
                run_kernel_packet_loop(
                    tun_fd, udp_sock, &uplink_str, host_ipv4, vpn1_spec, warp_spec, socks_cfg,
                    probe_rx, running, v1_tx, v1_rx, w_tx, w_rx, v1_hs, w_hs, w_ep,
                );
            })
            .map_err(|e| ChainError::SystemError(e.to_string()))?;
        self.workers.push(worker);
        info!("Sooya native Rust WarpKernel started for mode {:?}", config.mode);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        for port in self.probe_ports.drain(..) {
            let _ = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(5));
        }
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
    let listener = bind_reusable_tcp_listener(SocketAddr::from(([127, 0, 0, 1], port)))?;
    std::thread::Builder::new()
        .name(format!("sooya-probe-{}", port))
        .spawn(move || {
            for stream_res in listener.incoming() {
                if !running.load(Ordering::Relaxed) { break; }
                let Ok(mut stream) = stream_res else { continue };
                if !running.load(Ordering::Relaxed) { break; }
                let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(1200)));
                let mut req = [0u8; 512];
                if stream.read(&mut req).unwrap_or(0) == 0 || !running.load(Ordering::Relaxed) {
                    if !running.load(Ordering::Relaxed) { break; }
                    continue;
                }
                let (reply_tx, reply_rx) = mpsc::sync_channel(1);
                if probe_tx.send(ProbeJob { target, reply_tx }).is_err() { break; }
                let (status, body) = match reply_rx.recv_timeout(Duration::from_millis(4000)) {
                    Ok(Ok(b)) => ("200 OK", b),
                    Ok(Err(e)) => ("502 Bad Gateway", e),
                    Err(_) => ("504 Gateway Timeout", "Probe timeout".to_string()),
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status, body.len(), body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        })
        .map_err(|e| ChainError::SystemError(e.to_string()))
}

fn socks5_udp_associate(s5: &Socks5Config, _uplink: &str) -> Option<(TcpStream, SocketAddr)> {
    let server_addr = resolve_endpoint_addr(&s5.server, s5.port)?;
    let mut ctrl = TcpStream::connect_timeout(&server_addr, Duration::from_secs(4)).ok()?;
    let _ = ctrl.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = ctrl.set_write_timeout(Some(Duration::from_secs(4)));
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        set_socket_mark_and_device(ctrl.as_raw_fd(), _uplink);
    }
    let has_auth = s5.username.is_some();
    ctrl.write_all(if has_auth { &[0x05, 0x02, 0x00, 0x02] } else { &[0x05, 0x01, 0x00] }).ok()?;
    let mut rep = [0u8; 2];
    ctrl.read_exact(&mut rep).ok()?;
    if rep[0] != 0x05 { return None; }
    if rep[1] == 0x02 {
        let u = s5.username.as_deref().unwrap_or("");
        let p = s5.password.as_deref().unwrap_or("");
        let mut auth = Vec::with_capacity(3 + u.len() + p.len());
        auth.push(0x01);
        auth.push(u.len() as u8);
        auth.extend_from_slice(u.as_bytes());
        auth.push(p.len() as u8);
        auth.extend_from_slice(p.as_bytes());
        ctrl.write_all(&auth).ok()?;
        ctrl.read_exact(&mut rep).ok()?;
        if rep[1] != 0x00 { return None; }
    } else if rep[1] != 0x00 {
        return None;
    }
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).ok()?;
    let mut hdr = [0u8; 4];
    ctrl.read_exact(&mut hdr).ok()?;
    if hdr[1] != 0x00 { return None; }
    let relay_addr = match hdr[3] {
        0x01 => {
            let mut b = [0u8; 6];
            ctrl.read_exact(&mut b).ok()?;
            let mut ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            if ip.is_unspecified() {
                if let IpAddr::V4(sv4) = server_addr.ip() { ip = sv4; }
            }
            SocketAddr::new(IpAddr::V4(ip), u16::from_be_bytes([b[4], b[5]]))
        }
        _ => return None,
    };
    Some((ctrl, relay_addr))
}

#[allow(clippy::too_many_arguments)]
fn run_kernel_packet_loop(
    tun_fd: i32,
    udp_sock: UdpSocket,
    uplink: &str,
    host_ipv4: Ipv4Addr,
    vpn1_spec: Option<TunnelSpec>,
    warp_spec: Option<TunnelSpec>,
    socks_cfg: Option<Socks5Config>,
    probe_rx: mpsc::Receiver<ProbeJob>,
    running: Arc<AtomicBool>,
    vpn1_tx: Arc<AtomicU64>,
    vpn1_rx: Arc<AtomicU64>,
    warp_tx: Arc<AtomicU64>,
    warp_rx: Arc<AtomicU64>,
    vpn1_hs_ok: Arc<AtomicBool>,
    warp_hs_ok: Arc<AtomicBool>,
    active_warp_ep_shared: Arc<Mutex<Option<String>>>,
) {
    let mut vpn1_tunnel = vpn1_spec.as_ref().map(|s| {
        (WgTunnel::new(s.private_key, s.peer_public_key, s.preshared_key, s.reserved), s.endpoint)
    });
    let mut warp_tunnel = warp_spec.as_ref().map(|s| {
        WgTunnel::new(s.private_key, s.peer_public_key, s.preshared_key, s.reserved)
    });
    let socks_assoc = socks_cfg.as_ref().and_then(|s| socks5_udp_associate(s, uplink));
    let (_socks_ctrl, socks_relay) = match socks_assoc {
        Some((c, r)) => {
            vpn1_hs_ok.store(true, Ordering::Relaxed);
            (Some(c), Some(r))
        }
        None => (None, None),
    };

    let vpn1_v4 = vpn1_spec.as_ref().map(|s| s.local_v4).unwrap_or(Ipv4Addr::new(10, 2, 0, 2));
    let vpn1_v6 = vpn1_spec.as_ref().and_then(|s| s.local_v6);
    let warp_candidates = warp_spec.as_ref().map(|s| s.candidates.clone()).unwrap_or_default();
    let mut warp_cand_idx = 0usize;
    let mut active_warp_ep = warp_spec
        .as_ref()
        .map(|s| s.endpoint)
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(162, 159, 192, 1)), 2408));
    let warp_v4 = warp_spec.as_ref().map(|s| s.local_v4).unwrap_or(Ipv4Addr::new(172, 16, 0, 2));
    let warp_v6 = warp_spec.as_ref().and_then(|s| s.local_v6);
    let primary_dns = warp_spec.as_ref().or(vpn1_spec.as_ref()).map(|s| s.dns_v4).unwrap_or(Ipv4Addr::new(1, 1, 1, 1));

    let mut nat_table = L3NatTable::new(host_ipv4, Some(primary_dns));
    let mut active_probes: Vec<ActiveProbe> = Vec::with_capacity(4);
    let mut next_probe_port: u16 = 42100;
    let mut ip_id: u16 = 100;

    let mut tun_buf = [0u8; 4096];
    let mut udp_buf = [0u8; 4096];
    let mut wg1_buf = [0u8; 4096];
    let mut wg2_buf = [0u8; 4096];
    let mut wrap_buf = [0u8; 4096];
    let mut probe_buf = [0u8; 512];

    let mut last_vpn1_hs = Instant::now() - Duration::from_secs(10);
    let mut last_warp_hs = Instant::now() - Duration::from_secs(10);
    let mut had_work = false;

    let send_via_vpn1 = |pkt: &[u8], v1: &mut WgTunnel, vep: SocketAddr, sock: &UdpSocket, buf: &mut [u8], tx: &AtomicU64| {
        if let Some(n) = v1.encapsulate(pkt, buf) {
            if sock.send_to(&buf[..n], vep).is_ok() {
                tx.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    };

    let send_warp_frame = |wg2_frame: &[u8],
                           w_ep: SocketAddr,
                           v1_opt: &mut Option<(WgTunnel, SocketAddr)>,
                           s5_relay: Option<SocketAddr>,
                           sock: &UdpSocket,
                           ip_id: &mut u16,
                           w_buf: &mut [u8],
                           v1_buf: &mut [u8],
                           v1_tx: &AtomicU64,
                           w_tx: &AtomicU64| {
        w_tx.fetch_add(wg2_frame.len() as u64, Ordering::Relaxed);
        let dst_v4 = match w_ep.ip() { IpAddr::V4(v4) => v4, IpAddr::V6(_) => Ipv4Addr::new(162, 159, 192, 1) };
        if let Some((ref mut v1, vep)) = v1_opt {
            *ip_id = ip_id.wrapping_add(1);
            let wlen = wrap_ipv4_udp(wg2_frame, vpn1_v4, INNER_WG_SPORT, dst_v4, w_ep.port(), *ip_id, w_buf);
            send_via_vpn1(&w_buf[..wlen], v1, *vep, sock, v1_buf, v1_tx);
        } else if let Some(relay) = s5_relay {
            w_buf[0..4].copy_from_slice(&[0, 0, 0, 1]);
            w_buf[4..8].copy_from_slice(&dst_v4.octets());
            w_buf[8..10].copy_from_slice(&w_ep.port().to_be_bytes());
            w_buf[10..10 + wg2_frame.len()].copy_from_slice(wg2_frame);
            if sock.send_to(&w_buf[..10 + wg2_frame.len()], relay).is_ok() {
                v1_tx.fetch_add((10 + wg2_frame.len()) as u64, Ordering::Relaxed);
            }
        } else {
            let _ = sock.send_to(wg2_frame, w_ep);
        }
    };

    if let Some((ref mut v1, vep)) = vpn1_tunnel {
        let init = v1.format_handshake_initiation();
        let _ = udp_sock.send_to(&init, vep);
        vpn1_tx.fetch_add(148, Ordering::Relaxed);
        last_vpn1_hs = Instant::now();
    } else if let Some(ref mut w) = warp_tunnel {
        let init = w.format_handshake_initiation();
        send_warp_frame(&init, active_warp_ep, &mut vpn1_tunnel, socks_relay, &udp_sock, &mut ip_id, &mut wrap_buf, &mut wg1_buf, &vpn1_tx, &warp_tx);
        last_warp_hs = Instant::now();
    }

    while running.load(Ordering::Relaxed) {
        if let Some((ref mut v1, vep)) = vpn1_tunnel {
            v1.expire_if_dead();
            if !v1.has_session() {
                vpn1_hs_ok.store(false, Ordering::Relaxed);
            }
            let due = (!v1.has_session() && last_vpn1_hs.elapsed() >= Duration::from_millis(500))
                || (v1.needs_handshake() && last_vpn1_hs.elapsed() >= Duration::from_secs(3));
            if due {
                let init = v1.format_handshake_initiation();
                let _ = udp_sock.send_to(&init, vep);
                vpn1_tx.fetch_add(148, Ordering::Relaxed);
                last_vpn1_hs = Instant::now();
            } else if v1.needs_keepalive() {
                send_via_vpn1(&[], v1, vep, &udp_sock, &mut wg1_buf, &vpn1_tx);
            }
        }

        if let Some(ref mut w) = warp_tunnel {
            w.expire_if_dead();
            if !w.has_session() {
                warp_hs_ok.store(false, Ordering::Relaxed);
            }
            if vpn1_tunnel.as_ref().map(|(v, _)| v.has_session()).unwrap_or(true) {
                let no_sess_due = !w.has_session() && last_warp_hs.elapsed() >= Duration::from_millis(500);
                let rekey_due = w.needs_handshake() && last_warp_hs.elapsed() >= Duration::from_secs(3);
                if no_sess_due || rekey_due {
                    if no_sess_due && !warp_candidates.is_empty() {
                        active_warp_ep = warp_candidates[warp_cand_idx % warp_candidates.len()];
                        warp_cand_idx = warp_cand_idx.wrapping_add(1);
                    }
                    let init = w.format_handshake_initiation();
                    send_warp_frame(&init, active_warp_ep, &mut vpn1_tunnel, socks_relay, &udp_sock, &mut ip_id, &mut wrap_buf, &mut wg1_buf, &vpn1_tx, &warp_tx);
                    last_warp_hs = Instant::now();
                } else if w.needs_keepalive() {
                    if let Some(n) = w.encapsulate_keepalive(&mut wg2_buf) {
                        send_warp_frame(&wg2_buf[..n], active_warp_ep, &mut vpn1_tunnel, socks_relay, &udp_sock, &mut ip_id, &mut wrap_buf, &mut wg1_buf, &vpn1_tx, &warp_tx);
                    }
                }
            }
        }

        while let Ok(job) = probe_rx.try_recv() {
            next_probe_port = if next_probe_port >= 60000 { 42100 } else { next_probe_port + 1 };
            let lip = if job.target == ProbeTarget::Vpn1 { vpn1_v4 } else { warp_v4 };
            active_probes.push(ActiveProbe {
                target: job.target,
                fsm: TcpMicroProbe::new(lip, next_probe_port, Ipv4Addr::new(1, 1, 1, 1)),
                started_at: Instant::now(),
                last_tx: Instant::now() - Duration::from_secs(1),
                retries: 0,
                reply_tx: job.reply_tx,
            });
        }

        let mut idx = 0;
        while idx < active_probes.len() {
            if active_probes[idx].started_at.elapsed() > Duration::from_millis(5000) {
                let p = active_probes.swap_remove(idx);
                let _ = p.reply_tx.send(Err("Probe timed out".into()));
                continue;
            }
            let ready = match active_probes[idx].target {
                ProbeTarget::Vpn1 => vpn1_tunnel.as_ref().map(|(v, _)| v.has_session()).unwrap_or(false),
                ProbeTarget::Warp => warp_tunnel.as_ref().map(|w| w.has_session()).unwrap_or(false),
            };
            if ready && active_probes[idx].retries < 8 {
                let n = if !active_probes[idx].fsm.request_sent && active_probes[idx].last_tx.elapsed() >= Duration::from_millis(380) {
                    active_probes[idx].fsm.build_syn(&mut probe_buf)
                } else if active_probes[idx].fsm.request_sent && active_probes[idx].last_tx.elapsed() >= Duration::from_millis(650) {
                    active_probes[idx].fsm.retransmit_request(&mut probe_buf)
                } else {
                    0
                };
                if n > 0 {
                    active_probes[idx].last_tx = Instant::now();
                    active_probes[idx].retries += 1;
                    if active_probes[idx].target == ProbeTarget::Vpn1 {
                        if let Some((ref mut v1, vep)) = vpn1_tunnel {
                            send_via_vpn1(&probe_buf[..n], v1, vep, &udp_sock, &mut wg1_buf, &vpn1_tx);
                        }
                    } else if let Some(ref mut w) = warp_tunnel {
                        if let Some(wn) = w.encapsulate(&probe_buf[..n], &mut wg2_buf) {
                            send_warp_frame(&wg2_buf[..wn], active_warp_ep, &mut vpn1_tunnel, socks_relay, &udp_sock, &mut ip_id, &mut wrap_buf, &mut wg1_buf, &vpn1_tx, &warp_tx);
                        }
                    }
                }
            }
            idx += 1;
        }

        let all_ready = vpn1_tunnel.as_ref().map(|(v, _)| v.has_session()).unwrap_or(true)
            && warp_tunnel.as_ref().map(|w| w.has_session()).unwrap_or(true);
        let timeout_ms = if had_work {
            0
        } else if !all_ready || !active_probes.is_empty() {
            10
        } else {
            20
        };
        poll_fds(tun_fd, &udp_sock, timeout_ms);
        had_work = false;

        for _ in 0..256 {
            let Ok((udp_len, src_addr)) = udp_sock.recv_from(&mut udp_buf) else { break };
            had_work = true;
            if udp_len < 4 { continue; }

            let mut warp_in_slice: Option<(&[u8], SocketAddr)> = None;

            if let Some((ref mut v1, vep)) = vpn1_tunnel {
                vpn1_rx.fetch_add(udp_len as u64, Ordering::Relaxed);
                match v1.decapsulate(&udp_buf[..udp_len], &mut wg1_buf) {
                    DecapOutcome::None | DecapOutcome::Keepalive => {}
                    DecapOutcome::HandshakeCompleted { rtt_ms } => {
                        vpn1_hs_ok.store(true, Ordering::Relaxed);
                        info!("WireGuard handshake completed with {} (RTT: {} ms)", vep, rtt_ms);
                        if let Some(ka) = v1.encapsulate_keepalive(&mut tun_buf) {
                            let _ = udp_sock.send_to(&tun_buf[..ka], vep);
                            vpn1_tx.fetch_add(ka as u64, Ordering::Relaxed);
                        }
                        if let Some(ref mut w) = warp_tunnel {
                            if !w.has_session() {
                                let init = w.format_handshake_initiation();
                                send_warp_frame(&init, active_warp_ep, &mut vpn1_tunnel, socks_relay, &udp_sock, &mut ip_id, &mut wrap_buf, &mut tun_buf, &vpn1_tx, &warp_tx);
                                last_warp_hs = Instant::now();
                            }
                        }
                    }
                    DecapOutcome::IpPacket(pkt) => {
                        let plen = pkt.len();
                        let mut hit = false;
                        let mut pi = 0;
                        while pi < active_probes.len() {
                            if active_probes[pi].target == ProbeTarget::Vpn1 {
                                let (tx_n, body) = active_probes[pi].fsm.on_packet(&wg1_buf[..plen], &mut probe_buf);
                                if tx_n > 0 || body.is_some() {
                                    active_probes[pi].last_tx = Instant::now();
                                    hit = true;
                                    if tx_n > 0 {
                                        if let Some((ref mut v1_inner, vep_inner)) = vpn1_tunnel {
                                            send_via_vpn1(&probe_buf[..tx_n], v1_inner, vep_inner, &udp_sock, &mut wg2_buf, &vpn1_tx);
                                        }
                                    }
                                    if let Some(b) = body {
                                        let _ = active_probes.swap_remove(pi).reply_tx.send(Ok(b));
                                        break;
                                    }
                                }
                            }
                            pi += 1;
                        }
                        if hit { continue; }

                        if warp_tunnel.is_some() {
                            let ihl = ((wg1_buf[0] & 0x0f) as usize) * 4;
                            if plen >= ihl + 8 && (wg1_buf[0] >> 4) == 4 && wg1_buf[9] == 17 {
                                let sip = Ipv4Addr::new(wg1_buf[12], wg1_buf[13], wg1_buf[14], wg1_buf[15]);
                                let sport = u16::from_be_bytes([wg1_buf[ihl], wg1_buf[ihl + 1]]);
                                if let Some(inner_udp) = unwrap_ipv4_udp(&wg1_buf[..plen], INNER_WG_SPORT) {
                                    warp_in_slice = Some((inner_udp, SocketAddr::V4(SocketAddrV4::new(sip, sport))));
                                }
                            }
                        } else if nat_table.translate_inbound(&mut wg1_buf[..plen], TCP_MSS_CLAMP) {
                            write_tun(tun_fd, &wg1_buf[..plen]);
                        }
                    }
                }
            } else if socks_relay.is_some() {
                if udp_len > 10 && udp_buf[0..4] == [0, 0, 0, 1] {
                    vpn1_rx.fetch_add(udp_len as u64, Ordering::Relaxed);
                    let sip = Ipv4Addr::new(udp_buf[4], udp_buf[5], udp_buf[6], udp_buf[7]);
                    let sport = u16::from_be_bytes([udp_buf[8], udp_buf[9]]);
                    warp_in_slice = Some((&udp_buf[10..udp_len], SocketAddr::V4(SocketAddrV4::new(sip, sport))));
                }
            } else {
                warp_in_slice = Some((&udp_buf[..udp_len], src_addr));
            }

            if let (Some(ref mut w), Some((w_pkt, w_src))) = (&mut warp_tunnel, warp_in_slice) {
                warp_rx.fetch_add(w_pkt.len() as u64, Ordering::Relaxed);
                match w.decapsulate(w_pkt, &mut wg2_buf) {
                    DecapOutcome::None | DecapOutcome::Keepalive => {}
                    DecapOutcome::HandshakeCompleted { rtt_ms } => {
                        active_warp_ep = w_src;
                        *active_warp_ep_shared.lock().unwrap() = Some(active_warp_ep.to_string());
                        warp_hs_ok.store(true, Ordering::Relaxed);
                        info!("Cloudflare WARP handshake completed with {} (RTT: {} ms)", active_warp_ep, rtt_ms);
                        if let Some(ka) = w.encapsulate_keepalive(&mut tun_buf) {
                            send_warp_frame(&tun_buf[..ka], active_warp_ep, &mut vpn1_tunnel, socks_relay, &udp_sock, &mut ip_id, &mut wrap_buf, &mut wg1_buf, &vpn1_tx, &warp_tx);
                        }
                    }
                    DecapOutcome::IpPacket(app_pkt) => {
                        let alen = app_pkt.len();
                        let mut hit = false;
                        let mut pi = 0;
                        while pi < active_probes.len() {
                            if active_probes[pi].target == ProbeTarget::Warp {
                                let (tx_n, body) = active_probes[pi].fsm.on_packet(&wg2_buf[..alen], &mut probe_buf);
                                if tx_n > 0 || body.is_some() {
                                    active_probes[pi].last_tx = Instant::now();
                                    hit = true;
                                    if tx_n > 0 {
                                        if let Some(wn) = w.encapsulate(&probe_buf[..tx_n], &mut tun_buf) {
                                            send_warp_frame(&tun_buf[..wn], active_warp_ep, &mut vpn1_tunnel, socks_relay, &udp_sock, &mut ip_id, &mut wrap_buf, &mut wg1_buf, &vpn1_tx, &warp_tx);
                                        }
                                    }
                                    if let Some(b) = body {
                                        let _ = active_probes.swap_remove(pi).reply_tx.send(Ok(b));
                                        break;
                                    }
                                }
                            }
                            pi += 1;
                        }
                        if !hit && nat_table.translate_inbound(&mut wg2_buf[..alen], TCP_MSS_CLAMP) {
                            write_tun(tun_fd, &wg2_buf[..alen]);
                        }
                    }
                }
            }
        }

        for _ in 0..256 {
            let Some(pkt_len) = read_tun(tun_fd, &mut tun_buf) else { break };
            had_work = true;
            if pkt_len < 20 { continue; }
            let pkt = &mut tun_buf[..pkt_len];
            if let Some(ref mut w) = warp_tunnel {
                if nat_table.translate_outbound(pkt, warp_v4, warp_v6, TCP_MSS_CLAMP) {
                    if let Some(wn) = w.encapsulate(pkt, &mut wg2_buf) {
                        send_warp_frame(&wg2_buf[..wn], active_warp_ep, &mut vpn1_tunnel, socks_relay, &udp_sock, &mut ip_id, &mut wrap_buf, &mut wg1_buf, &vpn1_tx, &warp_tx);
                    }
                }
            } else if let Some((ref mut v1, vep)) = vpn1_tunnel {
                if nat_table.translate_outbound(pkt, vpn1_v4, vpn1_v6, TCP_MSS_CLAMP) {
                    send_via_vpn1(pkt, v1, vep, &udp_sock, &mut wg1_buf, &vpn1_tx);
                }
            }
        }
    }
    close_tun(tun_fd);
}

fn bind_reusable_tcp_listener(listen_addr: SocketAddr) -> Result<TcpListener> {
    let mut last_err = None;
    for attempt in 0..30 {
        match TcpListener::bind(listen_addr) {
            Ok(l) => return Ok(l),
            Err(e) => {
                last_err = Some(e);
                if attempt < 29 {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }
    Err(ChainError::NetworkError(format!(
        "SOCKS5 服务端绑定 {} 失败 (端口可能已被其他程序占用): {}",
        listen_addr,
        last_err.unwrap()
    )))
}

fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_link_local()
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00
                || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

fn dns_cache() -> &'static Mutex<HashMap<String, (Vec<Ipv4Addr>, Instant)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Vec<Ipv4Addr>, Instant)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn resolve_ipv4_via_tunnel_dns(host: &str, tunnel_active: bool) -> Option<Vec<Ipv4Addr>> {
    let key = host.to_ascii_lowercase();
    if let Ok(guard) = dns_cache().lock() {
        if let Some((ips, ts)) = guard.get(&key) {
            if ts.elapsed() < Duration::from_secs(120) && !ips.is_empty() {
                return Some(ips.clone());
            }
        }
    }

    static TXID_SEQ: AtomicU64 = AtomicU64::new(0x3a71);
    let txid = (TXID_SEQ.fetch_add(1, Ordering::Relaxed) as u16) | 1;
    let mut qbuf = [0u8; 512];
    let qlen = encode_dns_a_query(&key, txid, &mut qbuf)?;

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    #[cfg(target_os = "linux")]
    if tunnel_active {
        use std::os::unix::io::AsRawFd;
        set_outbound_tunnel_mark(sock.as_raw_fd());
    }
    #[cfg(not(target_os = "linux"))]
    let _ = tunnel_active;

    let mut rbuf = [0u8; 512];
    for dns_ip in [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)] {
        let dns_sa = SocketAddr::V4(SocketAddrV4::new(dns_ip, 53));
        if sock.send_to(&qbuf[..qlen], dns_sa).await.is_err() {
            continue;
        }
        if let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_millis(900), sock.recv_from(&mut rbuf)).await {
            let ips = parse_dns_a_response(&rbuf[..n], txid);
            if !ips.is_empty() {
                if let Ok(mut guard) = dns_cache().lock() {
                    if guard.len() >= 1024 {
                        guard.retain(|_, (_, ts)| ts.elapsed() < Duration::from_secs(120));
                    }
                    guard.insert(key, (ips.clone(), Instant::now()));
                }
                return Some(ips);
            }
        }
    }
    None
}

async fn resolve_socks5_target(target: &str, tunnel_active: bool) -> Option<Vec<SocketAddr>> {
    if let Ok(sa) = target.parse::<SocketAddr>() {
        return Some(vec![sa]);
    }
    let (host, port_str) = target.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(v4) = clean_host.parse::<Ipv4Addr>() {
        return Some(vec![SocketAddr::new(IpAddr::V4(v4), port)]);
    }
    if let Ok(v6) = clean_host.parse::<Ipv6Addr>() {
        return Some(vec![SocketAddr::new(IpAddr::V6(v6), port)]);
    }

    // Fast path: resolve IPv4 directly through the tunnel (or direct UDP) with in-memory TTL cache
    if let Some(ips) = resolve_ipv4_via_tunnel_dns(clean_host, tunnel_active).await {
        return Some(
            ips.into_iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
                .collect(),
        );
    }

    // Fallback to OS resolver with bounded timeout
    let resolved = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(target))
        .await
        .ok()?
        .ok()?;
    let addrs: Vec<SocketAddr> = resolved.collect();
    if addrs.is_empty() {
        return None;
    }
    let mut v4: Vec<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
    let v6: Vec<SocketAddr> = addrs.into_iter().filter(|a| a.is_ipv6()).collect();
    v4.extend(v6);
    Some(v4)
}

#[cfg(target_os = "linux")]
fn set_client_direct_mark(fd: i32) {
    use crate::network::iproute::MARK_PHYSICAL_DIRECT;
    let mark: u32 = MARK_PHYSICAL_DIRECT;
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, &mark as *const _ as *const _, 4);
    }
}

#[cfg(target_os = "linux")]
fn set_outbound_tunnel_mark(fd: i32) {
    use crate::network::iproute::MARK_HOST_PROXY;
    let mark: u32 = MARK_HOST_PROXY;
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, &mark as *const _ as *const _, 4);
    }
}

#[cfg(target_os = "linux")]
fn set_outbound_proxy_socket_opts(fd: i32, force_tunnel_mark: bool) {
    if force_tunnel_mark {
        set_outbound_tunnel_mark(fd);
    }
    let maxseg: libc::c_int = TCP_MSS_CLAMP as libc::c_int;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &maxseg as *const _ as *const _,
            4,
        );
    }
}

async fn connect_upstream_tcp(
    addrs: &[SocketAddr],
    tunnel_active: bool,
) -> std::io::Result<tokio::net::TcpStream> {
    let mut last_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses");
    for &addr in addrs {
        let sock_res = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        };
        let sock = match sock_res {
            Ok(s) => s,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let force_tunnel = tunnel_active && !is_private_or_local_ip(addr.ip());
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            set_outbound_proxy_socket_opts(sock.as_raw_fd(), force_tunnel);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = force_tunnel;

        match tokio::time::timeout(Duration::from_secs(6), sock.connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = e,
            Err(_) => {
                last_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout");
            }
        }
    }
    Err(last_err)
}

async fn run_native_socks5_server(
    listener: tokio::net::TcpListener,
    users: Vec<Socks5User>,
    running: Arc<AtomicBool>,
    tunnel_running: Arc<AtomicBool>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    tx_counter: Arc<AtomicU64>,
    rx_counter: Arc<AtomicU64>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let active_users: Vec<Socks5User> = users
        .into_iter()
        .filter(|u| !u.username.trim().is_empty())
        .collect();
    let users = Arc::new(active_users);

    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }
        let accept_res = tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            res = listener.accept() => res,
        };
        let Ok((mut client, _)) = accept_res else { break };
        let (users, tunnel_flag, tx_c, rx_c) = (
            users.clone(),
            tunnel_running.clone(),
            tx_counter.clone(),
            rx_counter.clone(),
        );
        tokio::spawn(async move {
            let _ = client.set_nodelay(true);
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::io::AsRawFd;
                set_client_direct_mark(client.as_raw_fd());
            }

            let mut b = [0u8; 512];
            let hs_res = tokio::time::timeout(Duration::from_secs(10), async {
                if client.read_exact(&mut b[..2]).await.is_err() || b[0] != 0x05 {
                    return None;
                }
                let nm = b[1] as usize;
                if nm == 0 || client.read_exact(&mut b[..nm]).await.is_err() {
                    return None;
                }
                let methods = &b[..nm];

                if users.is_empty() {
                    if methods.contains(&0x00) {
                        if client.write_all(&[0x05, 0x00]).await.is_err() {
                            return None;
                        }
                    } else if methods.contains(&0x02) {
                        if client.write_all(&[0x05, 0x02]).await.is_err() {
                            return None;
                        }
                        if client.read_exact(&mut b[..2]).await.is_err() || b[0] != 0x01 {
                            return None;
                        }
                        let ulen = b[1] as usize;
                        if client.read_exact(&mut b[..ulen + 1]).await.is_err() {
                            return None;
                        }
                        let plen = b[ulen] as usize;
                        if client.read_exact(&mut b[..plen]).await.is_err() {
                            return None;
                        }
                        if client.write_all(&[0x01, 0x00]).await.is_err() {
                            return None;
                        }
                    } else {
                        let _ = client.write_all(&[0x05, 0xFF]).await;
                        return None;
                    }
                } else {
                    if !methods.contains(&0x02) {
                        let _ = client.write_all(&[0x05, 0xFF]).await;
                        return None;
                    }
                    if client.write_all(&[0x05, 0x02]).await.is_err() {
                        return None;
                    }
                    if client.read_exact(&mut b[..2]).await.is_err() || b[0] != 0x01 {
                        return None;
                    }
                    let ulen = b[1] as usize;
                    if client.read_exact(&mut b[..ulen + 1]).await.is_err() {
                        return None;
                    }
                    let uname = String::from_utf8_lossy(&b[..ulen]).into_owned();
                    let plen = b[ulen] as usize;
                    if client.read_exact(&mut b[..plen]).await.is_err() {
                        return None;
                    }
                    let upass = String::from_utf8_lossy(&b[..plen]).into_owned();
                    if !users.iter().any(|u| u.username == uname && u.password == upass) {
                        let _ = client.write_all(&[0x01, 0x01]).await;
                        return None;
                    }
                    if client.write_all(&[0x01, 0x00]).await.is_err() {
                        return None;
                    }
                }

                if client.read_exact(&mut b[..4]).await.is_err() || b[0] != 0x05 {
                    return None;
                }
                let cmd = b[1];
                let atyp = b[3];
                let target = match atyp {
                    0x01 => {
                        if client.read_exact(&mut b[..6]).await.is_err() {
                            return None;
                        }
                        format!(
                            "{}:{}",
                            Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                            u16::from_be_bytes([b[4], b[5]])
                        )
                    }
                    0x03 => {
                        if client.read_exact(&mut b[..1]).await.is_err() {
                            return None;
                        }
                        let dl = b[0] as usize;
                        if client.read_exact(&mut b[..dl + 2]).await.is_err() {
                            return None;
                        }
                        format!(
                            "{}:{}",
                            String::from_utf8_lossy(&b[..dl]),
                            u16::from_be_bytes([b[dl], b[dl + 1]])
                        )
                    }
                    0x04 => {
                        if client.read_exact(&mut b[..18]).await.is_err() {
                            return None;
                        }
                        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap());
                        format!("[{}]:{}", ip, u16::from_be_bytes([b[16], b[17]]))
                    }
                    _ => {
                        let _ = client
                            .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                        return None;
                    }
                };
                Some((cmd, target))
            })
            .await;

            let Ok(Some((cmd, target))) = hs_res else {
                return;
            };
            let tunnel_active = tunnel_flag.load(Ordering::Relaxed);

            if cmd == 0x03 {
                // SOCKS5 UDP Associate
                let local_ip = client
                    .local_addr()
                    .map(|a| match a.ip() {
                        IpAddr::V4(v4) => v4,
                        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                    })
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);
                let Ok(client_udp) =
                    tokio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(local_ip), 0)).await
                else {
                    let _ = client
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                };
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::io::AsRawFd;
                    set_client_direct_mark(client_udp.as_raw_fd());
                }
                let Ok(up_udp) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
                    let _ = client
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                };
                #[cfg(target_os = "linux")]
                if tunnel_active {
                    use std::os::unix::io::AsRawFd;
                    set_outbound_tunnel_mark(up_udp.as_raw_fd());
                }
                let bound_port = client_udp.local_addr().map(|a| a.port()).unwrap_or(0);
                let mut reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                reply[4..8].copy_from_slice(&local_ip.octets());
                reply[8..10].copy_from_slice(&bound_port.to_be_bytes());
                if client.write_all(&reply).await.is_err() {
                    return;
                }

                let mut c_buf = [0u8; 2048];
                let mut u_buf = [0u8; 2048];
                let mut tcp_eof = [0u8; 16];
                let mut last_c_addr: Option<SocketAddr> = None;
                loop {
                    tokio::select! {
                        res = client.read(&mut tcp_eof) => {
                            if res.unwrap_or(0) == 0 { break; }
                        }
                        Ok((n, c_addr)) = client_udp.recv_from(&mut c_buf) => {
                            if n <= 10 || c_buf[2] != 0 { continue; }
                            last_c_addr = Some(c_addr);
                            let (dst_sa, hdr_len) = match c_buf[3] {
                                0x01 if n > 10 => {
                                    let ip = Ipv4Addr::new(c_buf[4], c_buf[5], c_buf[6], c_buf[7]);
                                    let port = u16::from_be_bytes([c_buf[8], c_buf[9]]);
                                    (Some(SocketAddr::V4(SocketAddrV4::new(ip, port))), 10usize)
                                }
                                0x03 if n > 5 => {
                                    let dl = c_buf[4] as usize;
                                    if n <= 7 + dl { continue; }
                                    let dst_str = format!(
                                        "{}:{}",
                                        String::from_utf8_lossy(&c_buf[5..5 + dl]),
                                        u16::from_be_bytes([c_buf[5 + dl], c_buf[6 + dl]])
                                    );
                                    let sa = resolve_socks5_target(&dst_str, tunnel_active)
                                        .await
                                        .and_then(|v| v.into_iter().next());
                                    (sa, 7 + dl)
                                }
                                _ => continue,
                            };
                            if let Some(sa) = dst_sa {
                                let payload = &c_buf[hdr_len..n];
                                if up_udp.send_to(payload, sa).await.is_ok() {
                                    tx_c.fetch_add(payload.len() as u64, Ordering::Relaxed);
                                }
                            }
                        }
                        Ok((n, r_addr)) = up_udp.recv_from(&mut u_buf[10..]) => {
                            if let (Some(c_addr), IpAddr::V4(rv4)) = (last_c_addr, r_addr.ip()) {
                                u_buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                                u_buf[4..8].copy_from_slice(&rv4.octets());
                                u_buf[8..10].copy_from_slice(&r_addr.port().to_be_bytes());
                                if client_udp.send_to(&u_buf[..10 + n], c_addr).await.is_ok() {
                                    rx_c.fetch_add(n as u64, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
                return;
            }

            if cmd != 0x01 {
                let _ = client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }

            let Some(addrs) = resolve_socks5_target(&target, tunnel_active).await else {
                let _ = client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            };

            match connect_upstream_tcp(&addrs, tunnel_active).await {
                Ok(mut up) => {
                    if client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.is_ok() {
                        if let Ok((tx, rx)) =
                            tokio::io::copy_bidirectional_with_sizes(&mut client, &mut up, 32768, 32768)
                                .await
                        {
                            tx_c.fetch_add(tx, Ordering::Relaxed);
                            rx_c.fetch_add(rx, Ordering::Relaxed);
                        }
                    }
                }
                Err(_) => {
                    let _ = client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                }
            }
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_and_configure_tun(name: &str, enable_ipv6: bool, mtu: u16) -> Result<i32> {
    use crate::network::iproute::IpRouteManager;
    use std::ffi::CString;

    IpRouteManager::ensure_tun_device()?;
    let c_path = CString::new("/dev/net/tun").unwrap();
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd < 0 {
        return Err(ChainError::NetworkError(format!("open /dev/net/tun: {}", std::io::Error::last_os_error())));
    }
    #[repr(C)]
    struct IfReq {
        ifr_name: [u8; 16],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }
    let mut ifr = IfReq { ifr_name: [0u8; 16], ifr_flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short, _pad: [0u8; 22] };
    let nb = name.as_bytes();
    ifr.ifr_name[..nb.len().min(15)].copy_from_slice(&nb[..nb.len().min(15)]);
    if unsafe { libc::ioctl(fd, 0x400454ca, &mut ifr) } < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(ChainError::NetworkError(format!("TUNSETIFF {} failed: {}", name, err)));
    }
    let mtu_str = mtu.to_string();
    let mut cmds = vec![
        vec!["addr".into(), "add".into(), format!("{}/30", TUN_IPV4), "dev".into(), name.into()],
        vec!["link".into(), "set".into(), "dev".into(), name.into(), "mtu".into(), mtu_str, "up".into()],
    ];
    if enable_ipv6 {
        cmds.insert(1, vec!["addr".into(), "add".into(), "fdfe:dcba:9876::1/126".into(), "dev".into(), name.into()]);
    }
    for args in &cmds {
        if let Err(e) = IpRouteManager::run(&args.iter().map(String::as_str).collect::<Vec<_>>()) {
            unsafe { libc::close(fd); }
            return Err(e);
        }
    }
    Ok(fd)
}

#[cfg(not(target_os = "linux"))]
fn create_and_configure_tun(_name: &str, _enable_ipv6: bool, _mtu: u16) -> Result<i32> { Ok(-1) }

#[cfg(target_os = "linux")]
fn set_socket_mark_and_device(fd: i32, uplink: &str) {
    use crate::network::iproute::MARK_PHYSICAL_DIRECT;
    use std::ffi::CString;
    let mark: u32 = MARK_PHYSICAL_DIRECT;
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, &mark as *const _ as *const _, 4);
        if !uplink.is_empty() {
            if let Ok(c_if) = CString::new(uplink) {
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, c_if.as_ptr() as *const _, (uplink.len() + 1) as _);
            }
        }
        let sz: libc::c_int = 2 * 1024 * 1024;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &sz as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &sz as *const _ as *const _, 4);
    }
}

#[cfg(target_os = "linux")]
fn create_marked_udp_socket(uplink: &str) -> Result<UdpSocket> {
    use std::os::unix::io::AsRawFd;
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| ChainError::NetworkError(e.to_string()))?;
    let _ = sock.set_nonblocking(true);
    set_socket_mark_and_device(sock.as_raw_fd(), uplink);
    Ok(sock)
}

#[cfg(not(target_os = "linux"))]
fn create_marked_udp_socket(_uplink: &str) -> Result<UdpSocket> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| ChainError::NetworkError(e.to_string()))?;
    let _ = sock.set_nonblocking(true);
    Ok(sock)
}

#[cfg(target_os = "linux")]
fn poll_fds(tun_fd: i32, udp_sock: &UdpSocket, timeout_ms: i32) {
    use std::os::unix::io::AsRawFd;
    let mut fds = [
        libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: udp_sock.as_raw_fd(), events: libc::POLLIN, revents: 0 },
    ];
    unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms); }
}

#[cfg(not(target_os = "linux"))]
fn poll_fds(_tun_fd: i32, _udp_sock: &UdpSocket, timeout_ms: i32) {
    if timeout_ms > 0 {
        std::thread::sleep(Duration::from_millis(timeout_ms as u64));
    }
}

#[cfg(target_os = "linux")]
fn read_tun(tun_fd: i32, buf: &mut [u8]) -> Option<usize> {
    if tun_fd < 0 { return None; }
    let n = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    (n > 0).then_some(n as usize)
}

#[cfg(not(target_os = "linux"))]
fn read_tun(_tun_fd: i32, _buf: &mut [u8]) -> Option<usize> { None }

#[cfg(target_os = "linux")]
fn write_tun(tun_fd: i32, buf: &[u8]) {
    if tun_fd >= 0 && !buf.is_empty() {
        unsafe { let _ = libc::write(tun_fd, buf.as_ptr() as *const _, buf.len()); }
    }
}

#[cfg(not(target_os = "linux"))]
fn write_tun(_tun_fd: i32, _buf: &[u8]) {}

#[cfg(target_os = "linux")]
fn close_tun(tun_fd: i32) {
    if tun_fd >= 0 { unsafe { libc::close(tun_fd); } }
}

#[cfg(not(target_os = "linux"))]
fn close_tun(_tun_fd: i32) {}
