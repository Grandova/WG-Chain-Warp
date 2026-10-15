use crate::error::{ChainError, Result};
use crate::model::config::{ChainProxyConfig, ParsedNodes, ProxyMode, Socks5Config, Socks5User};
use crate::warp_kernel::endpoint::{build_warp_candidates, resolve_endpoint_addr};
use crate::warp_kernel::noise::{DecapOutcome, WgTunnel};
use crate::warp_kernel::pkt::{unwrap_ipv4_udp, wrap_ipv4_udp, L3NatTable, TcpMicroProbe};
use crate::warp_kernel::{TEST_VPN1_PORT, TEST_WARP_PORT};
use crate::wireguard::model::WgConfig;
use base64::prelude::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
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

pub struct WarpKernel {
    running: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    tokio_abort_handles: Vec<tokio::task::AbortHandle>,
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
            tokio_abort_handles: Vec::new(),
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
            for cmd in [["stop", "warp-svc"], ["disable", "warp-svc"]] {
                let _ = std::process::Command::new("systemctl").args(cmd).output();
            }
            let _ = std::process::Command::new("pkill").args(["-9", "-f", "warp-svc"]).output();
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

        if config.mode == ProxyMode::Socks5Server && config.socks5_server.is_none() {
            return Err(ChainError::ValidationError("Missing SOCKS5 server config".into()));
        }
        if let Some(ref srv) = config.socks5_server {
            if srv.port > 0 {
                srv.validate()?;
                let listen_addr = SocketAddr::new(srv.listen, srv.port);
                let std_listener = TcpListener::bind(listen_addr).map_err(|e| {
                    ChainError::NetworkError(format!("SOCKS5 服务端绑定 {} 失败 (端口可能已被占用): {}", listen_addr, e))
                })?;
                std_listener
                    .set_nonblocking(true)
                    .map_err(|e| ChainError::NetworkError(format!("SOCKS5 set_nonblocking failed: {}", e)))?;
                let tokio_listener = tokio::net::TcpListener::from_std(std_listener)
                    .map_err(|e| ChainError::NetworkError(format!("SOCKS5 tokio listener failed: {}", e)))?;
                self.running.store(true, Ordering::SeqCst);
                let (running, tx, rx) = (self.running.clone(), self.vpn1_tx.clone(), self.vpn1_rx.clone());
                let users = srv.users.clone();
                let h = tokio::spawn(async move {
                    let _ = run_native_socks5_server(tokio_listener, users, running, tx, rx).await;
                });
                self.tokio_abort_handles.push(h.abort_handle());
                info!("Sooya native SOCKS5 server listening on {}", listen_addr);
                if config.mode == ProxyMode::Socks5Server {
                    self.vpn1_hs_ok.store(true, Ordering::Relaxed);
                    return Ok(());
                }
            }
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

        let tun_fd = create_and_configure_tun("chain0", config.routing.ipv6)?;
        let udp_sock = create_marked_udp_socket(uplink)?;
        let (probe_tx, probe_rx) = mpsc::sync_channel::<ProbeJob>(16);
        self.running.store(true, Ordering::SeqCst);

        if config.mode == ProxyMode::WgChainWarp {
            if let Ok(h1) = spawn_probe_http_listener(TEST_VPN1_PORT, ProbeTarget::Vpn1, probe_tx.clone(), self.running.clone()) {
                self.workers.push(h1);
            }
        }
        let main_target = if config.mode == ProxyMode::StandaloneWg { ProbeTarget::Vpn1 } else { ProbeTarget::Warp };
        if let Ok(h2) = spawn_probe_http_listener(TEST_WARP_PORT, main_target, probe_tx, self.running.clone()) {
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
        for abort in self.tokio_abort_handles.drain(..) {
            abort.abort();
        }
        for port in [TEST_VPN1_PORT, TEST_WARP_PORT] {
            let _ = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(10));
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
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| ChainError::NetworkError(format!("Probe bind 127.0.0.1:{} failed: {}", port, e)))?;
    std::thread::Builder::new()
        .name(format!("sooya-probe-{}", port))
        .spawn(move || {
            for stream_res in listener.incoming() {
                if !running.load(Ordering::Relaxed) { break; }
                let Ok(mut stream) = stream_res else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
                let mut req = [0u8; 512];
                if stream.read(&mut req).unwrap_or(0) == 0 || !running.load(Ordering::Relaxed) { continue; }
                let (reply_tx, reply_rx) = mpsc::sync_channel(1);
                if probe_tx.send(ProbeJob { target, reply_tx }).is_err() { break; }
                let (status, body) = match reply_rx.recv_timeout(Duration::from_millis(5500)) {
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

    let mut tun_buf = [0u8; 2048];
    let mut udp_buf = [0u8; 2048];
    let mut wg1_buf = [0u8; 2048];
    let mut wg2_buf = [0u8; 2048];
    let mut wrap_buf = [0u8; 2048];
    let mut probe_buf = [0u8; 512];

    let mut last_vpn1_hs = Instant::now() - Duration::from_secs(10);
    let mut last_warp_hs = Instant::now() - Duration::from_secs(10);

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
            let due = (!v1.has_session() && last_vpn1_hs.elapsed() >= Duration::from_millis(1200))
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
            if vpn1_tunnel.as_ref().map(|(v, _)| v.has_session()).unwrap_or(true) {
                let no_sess_due = !w.has_session() && last_warp_hs.elapsed() >= Duration::from_millis(1100);
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
        poll_fds(tun_fd, &udp_sock, if !all_ready || !active_probes.is_empty() { 25 } else { 250 });

        for _ in 0..64 {
            let Ok((udp_len, src_addr)) = udp_sock.recv_from(&mut udp_buf) else { break };
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

        for _ in 0..64 {
            let Some(pkt_len) = read_tun(tun_fd, &mut tun_buf) else { break };
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

async fn run_native_socks5_server(
    listener: tokio::net::TcpListener,
    users: Vec<Socks5User>,
    running: Arc<AtomicBool>,
    tx_counter: Arc<AtomicU64>,
    rx_counter: Arc<AtomicU64>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream as TokioStream;

    let active_users: Vec<Socks5User> = users
        .into_iter()
        .filter(|u| !u.username.trim().is_empty())
        .collect();
    let users = Arc::new(active_users);

    while running.load(Ordering::Relaxed) {
        let Ok((mut client, _)) = listener.accept().await else { break };
        let (users, tx_c, rx_c) = (users.clone(), tx_counter.clone(), rx_counter.clone());
        tokio::spawn(async move {
            let _ = client.set_nodelay(true);
            let mut b = [0u8; 512];
            if client.read_exact(&mut b[..2]).await.is_err() || b[0] != 0x05 { return; }
            let nm = b[1] as usize;
            if nm == 0 || client.read_exact(&mut b[..nm]).await.is_err() { return; }
            let methods = &b[..nm];

            if users.is_empty() {
                if methods.contains(&0x00) {
                    if client.write_all(&[0x05, 0x00]).await.is_err() { return; }
                } else if methods.contains(&0x02) {
                    if client.write_all(&[0x05, 0x02]).await.is_err() { return; }
                    if client.read_exact(&mut b[..2]).await.is_err() || b[0] != 0x01 { return; }
                    let ulen = b[1] as usize;
                    if client.read_exact(&mut b[..ulen + 1]).await.is_err() { return; }
                    let plen = b[ulen] as usize;
                    if client.read_exact(&mut b[..plen]).await.is_err() { return; }
                    if client.write_all(&[0x01, 0x00]).await.is_err() { return; }
                } else {
                    let _ = client.write_all(&[0x05, 0xFF]).await;
                    return;
                }
            } else {
                if !methods.contains(&0x02) {
                    let _ = client.write_all(&[0x05, 0xFF]).await;
                    return;
                }
                if client.write_all(&[0x05, 0x02]).await.is_err() { return; }
                if client.read_exact(&mut b[..2]).await.is_err() || b[0] != 0x01 { return; }
                let ulen = b[1] as usize;
                if client.read_exact(&mut b[..ulen + 1]).await.is_err() { return; }
                let uname = String::from_utf8_lossy(&b[..ulen]).into_owned();
                let plen = b[ulen] as usize;
                if client.read_exact(&mut b[..plen]).await.is_err() { return; }
                let upass = String::from_utf8_lossy(&b[..plen]).into_owned();
                if !users.iter().any(|u| u.username == uname && u.password == upass) {
                    let _ = client.write_all(&[0x01, 0x01]).await;
                    return;
                }
                if client.write_all(&[0x01, 0x00]).await.is_err() { return; }
            }

            if client.read_exact(&mut b[..4]).await.is_err() || b[0] != 0x05 { return; }
            let cmd = b[1];
            let atyp = b[3];
            let target = match atyp {
                0x01 => {
                    if client.read_exact(&mut b[..6]).await.is_err() { return; }
                    format!("{}:{}", Ipv4Addr::new(b[0], b[1], b[2], b[3]), u16::from_be_bytes([b[4], b[5]]))
                }
                0x03 => {
                    if client.read_exact(&mut b[..1]).await.is_err() { return; }
                    let dl = b[0] as usize;
                    if client.read_exact(&mut b[..dl + 2]).await.is_err() { return; }
                    format!("{}:{}", String::from_utf8_lossy(&b[..dl]), u16::from_be_bytes([b[dl], b[dl + 1]]))
                }
                0x04 => {
                    if client.read_exact(&mut b[..18]).await.is_err() { return; }
                    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap());
                    format!("[{}]:{}", ip, u16::from_be_bytes([b[16], b[17]]))
                }
                _ => {
                    let _ = client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return;
                }
            };
            if cmd != 0x01 {
                let _ = client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
            match tokio::time::timeout(Duration::from_secs(10), TokioStream::connect(&target)).await {
                Ok(Ok(mut up)) => {
                    let _ = up.set_nodelay(true);
                    if client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.is_ok() {
                        if let Ok((tx, rx)) = tokio::io::copy_bidirectional(&mut client, &mut up).await {
                            tx_c.fetch_add(tx, Ordering::Relaxed);
                            rx_c.fetch_add(rx, Ordering::Relaxed);
                        }
                    }
                }
                _ => {
                    let _ = client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
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
    let mut cmds = vec![
        vec!["addr".into(), "add".into(), format!("{}/30", TUN_IPV4), "dev".into(), name.into()],
        vec!["link".into(), "set".into(), "dev".into(), name.into(), "mtu".into(), "1280".into(), "up".into()],
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
fn create_and_configure_tun(_name: &str, _enable_ipv6: bool) -> Result<i32> { Ok(-1) }

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
    std::thread::sleep(Duration::from_millis(timeout_ms.max(1) as u64));
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
