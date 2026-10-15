use crate::warp_kernel::noise::WgTunnel;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

pub const WARP_ANYCAST_IPV4: [Ipv4Addr; 7] = [
    Ipv4Addr::new(162, 159, 192, 1),
    Ipv4Addr::new(188, 114, 96, 1),
    Ipv4Addr::new(162, 159, 193, 1),
    Ipv4Addr::new(188, 114, 97, 1),
    Ipv4Addr::new(162, 159, 195, 1),
    Ipv4Addr::new(188, 114, 98, 1),
    Ipv4Addr::new(188, 114, 99, 1),
];

pub const WARP_ANYCAST_PORTS: [u16; 4] = [2408, 500, 4500, 1701];

/// Resolve a host:port endpoint into a SocketAddr (preferring IPv4 for stability).
pub fn resolve_endpoint_addr(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    let clean = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    if let Ok(iter) = (clean, port).to_socket_addrs() {
        let addrs: Vec<SocketAddr> = iter.collect();
        if let Some(v4) = addrs.iter().find(|a| a.is_ipv4()) {
            return Some(*v4);
        }
        return addrs.into_iter().next();
    }
    None
}

/// Build an ordered list of Cloudflare WARP Anycast endpoint candidates for Happy-Eyeballs failover.
/// Places the configured endpoint first, followed by alternate ports on the same IP,
/// followed by diverse Anycast IP blocks (162.159.x.x and 188.114.x.x) across UDP ports 2408, 500, 4500, 1701.
pub fn build_warp_candidates(configured: Option<SocketAddr>) -> Vec<SocketAddr> {
    let mut list = Vec::with_capacity(32);
    let mut push_unique = |addr: SocketAddr| {
        if !list.contains(&addr) {
            list.push(addr);
        }
    };

    if let Some(cfg) = configured {
        push_unique(cfg);
        for &port in &WARP_ANYCAST_PORTS {
            push_unique(SocketAddr::new(cfg.ip(), port));
        }
    }

    // Interleave ports and distinct /16 Anycast prefixes so a blocked port or prefix is bypassed immediately
    for &port in &WARP_ANYCAST_PORTS {
        for &ip in &WARP_ANYCAST_IPV4 {
            push_unique(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }

    list
}

/// Race a real WireGuard Type-1 Handshake Initiation against candidate WARP endpoints directly
/// to select the lowest-latency reachable endpoint.
pub fn select_best_warp_endpoint(
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    reserved: [u8; 3],
    configured: Option<SocketAddr>,
    timeout: Duration,
) -> Option<(SocketAddr, u64)> {
    let candidates = build_warp_candidates(configured);
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(80)));

    let mut tunnel = WgTunnel::new(private_key, peer_public_key, [0u8; 32], reserved);
    let init_pkt = tunnel.format_handshake_initiation();

    let start = Instant::now();
    let mut buf = [0u8; 256];

    // Send probes in small staggered batches of 4 candidates
    for chunk in candidates.chunks(4) {
        if start.elapsed() >= timeout {
            break;
        }
        let batch_sent = Instant::now();
        for &addr in chunk {
            let _ = sock.send_to(&init_pkt, addr);
        }
        while batch_sent.elapsed() < Duration::from_millis(140) {
            if let Ok((n, from)) = sock.recv_from(&mut buf) {
                if n >= 92 && buf[0] == 2 {
                    let rtt = batch_sent.elapsed().as_millis() as u64;
                    return Some((from, rtt.max(1)));
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_warp_candidates_ordering_and_uniqueness() {
        let custom: SocketAddr = "162.159.192.1:2408".parse().unwrap();
        let cands = build_warp_candidates(Some(custom));
        assert!(!cands.is_empty());
        assert_eq!(cands[0], custom);
        // Ensure alternative ports on the configured IP come next
        assert_eq!(cands[1], "162.159.192.1:500".parse().unwrap());
        assert_eq!(cands[2], "162.159.192.1:4500".parse().unwrap());
        // Ensure no duplicates exist
        for i in 0..cands.len() {
            for j in (i + 1)..cands.len() {
                assert_ne!(cands[i], cands[j]);
            }
        }
    }
}
