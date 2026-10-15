use crate::warp_kernel::noise::WgTunnel;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

pub const WARP_PORTS: [u16; 4] = [2408, 500, 4500, 1701];

pub const WARP_ANYCAST_IPV4S: [Ipv4Addr; 8] = [
    Ipv4Addr::new(162, 159, 192, 1),
    Ipv4Addr::new(162, 159, 193, 10),
    Ipv4Addr::new(162, 159, 195, 1),
    Ipv4Addr::new(188, 114, 96, 1),
    Ipv4Addr::new(188, 114, 97, 3),
    Ipv4Addr::new(188, 114, 98, 1),
    Ipv4Addr::new(188, 114, 99, 1),
    Ipv4Addr::new(162, 159, 192, 5),
];

pub fn build_warp_candidates(configured: Option<SocketAddr>) -> Vec<SocketAddr> {
    let mut list = Vec::with_capacity(20);
    if let Some(cfg) = configured {
        list.push(cfg);
        for &p in &WARP_PORTS {
            let alt = SocketAddr::new(cfg.ip(), p);
            if !list.contains(&alt) { list.push(alt); }
        }
    }
    for &port in &WARP_PORTS {
        for &ip in &WARP_ANYCAST_IPV4S {
            let cand = SocketAddr::new(IpAddr::V4(ip), port);
            if !list.contains(&cand) { list.push(cand); }
        }
    }
    list
}

pub fn select_best_warp_endpoint(
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    reserved: [u8; 3],
    configured: Option<SocketAddr>,
    timeout: Duration,
) -> Option<(SocketAddr, u64)> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = sock.set_nonblocking(true);
    let mut tunnel = WgTunnel::new(private_key, peer_public_key, [0u8; 32], reserved);
    let init_pkt = tunnel.format_handshake_initiation();
    let start = Instant::now();
    for cand in build_warp_candidates(configured).into_iter().take(12) {
        let _ = sock.send_to(&init_pkt, cand);
    }
    let mut buf = [0u8; 256];
    while start.elapsed() < timeout {
        if let Ok((n, src)) = sock.recv_from(&mut buf) {
            if n >= 92 && buf[0] == 2 && tunnel.consume_handshake_response(&buf[..n]).is_some() {
                return Some((src, start.elapsed().as_millis() as u64));
            }
        }
        std::thread::sleep(Duration::from_millis(8));
    }
    None
}

pub fn resolve_endpoint_addr(host: &str, port: u16) -> Option<SocketAddr> {
    let clean = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    let addrs: Vec<SocketAddr> = format!("{}:{}", clean, port).to_socket_addrs().ok()?.collect();
    addrs.iter().find(|a| a.is_ipv4()).copied().or_else(|| addrs.first().copied())
}
