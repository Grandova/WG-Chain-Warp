use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[inline]
pub fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let len = hdr.len() & !1;
    let mut i = 0;
    while i < len {
        if i != 10 {
            sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        }
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[inline]
fn l4_checksum_v4(src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8, l4: &[u8], skip_offset: usize) -> u16 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += proto as u32;
    sum += l4.len() as u32;

    let mut i = 0;
    while i + 1 < l4.len() {
        if i != skip_offset {
            sum += u16::from_be_bytes([l4[i], l4[i + 1]]) as u32;
        }
        i += 2;
    }
    if i < l4.len() {
        sum += (l4[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    if proto == 17 && res == 0 {
        0xffff
    } else {
        res
    }
}

#[inline]
fn l4_checksum_v6(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    next_hdr: u8,
    l4: &[u8],
    skip_offset: usize,
) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src_ip.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst_ip.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = l4.len() as u32;
    sum += len >> 16;
    sum += len & 0xffff;
    sum += next_hdr as u32;

    let mut i = 0;
    while i + 1 < l4.len() {
        if i != skip_offset {
            sum += u16::from_be_bytes([l4[i], l4[i + 1]]) as u32;
        }
        i += 2;
    }
    if i < l4.len() {
        sum += (l4[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    if next_hdr == 17 && res == 0 {
        0xffff
    } else {
        res
    }
}

/// Clamp TCP Maximum Segment Size (MSS) option in SYN / SYN-ACK packets in-place
pub fn clamp_tcp_mss(pkt: &mut [u8], max_mss: u16) {
    if pkt.is_empty() {
        return;
    }
    let version = pkt[0] >> 4;
    let tcp_offset = if version == 4 {
        if pkt.len() < 40 {
            return;
        }
        if pkt[9] != 6 {
            return;
        }
        ((pkt[0] & 0x0f) as usize) * 4
    } else if version == 6 {
        if pkt.len() < 60 {
            return;
        }
        if pkt[6] != 6 {
            return;
        }
        40
    } else {
        return;
    };

    if pkt.len() < tcp_offset + 20 {
        return;
    }
    let flags = pkt[tcp_offset + 13];
    if (flags & 0x02) == 0 {
        // Not a SYN packet
        return;
    }

    let data_offset = ((pkt[tcp_offset + 12] >> 4) as usize) * 4;
    let opts_end = (tcp_offset + data_offset).min(pkt.len());
    let mut idx = tcp_offset + 20;

    while idx < opts_end {
        let kind = pkt[idx];
        if kind == 0 {
            break; // End of option list
        }
        if kind == 1 {
            idx += 1; // NOP
            continue;
        }
        if idx + 1 >= opts_end {
            break;
        }
        let opt_len = pkt[idx + 1] as usize;
        if opt_len < 2 || idx + opt_len > opts_end {
            break;
        }
        if kind == 2 && opt_len == 4 {
            let cur_mss = u16::from_be_bytes([pkt[idx + 2], pkt[idx + 3]]);
            if cur_mss > max_mss {
                pkt[idx + 2..idx + 4].copy_from_slice(&max_mss.to_be_bytes());
            }
            break;
        }
        idx += opt_len;
    }
}

/// Recompute IPv4 header checksum and TCP/UDP checksum
pub fn recompute_ipv4_checksums(pkt: &mut [u8]) {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl {
        return;
    }
    let ip_len = (u16::from_be_bytes([pkt[2], pkt[3]]) as usize).min(pkt.len());
    let proto = pkt[9];
    let src_ip = [pkt[12], pkt[13], pkt[14], pkt[15]];
    let dst_ip = [pkt[16], pkt[17], pkt[18], pkt[19]];

    let hdr_csum = ipv4_header_checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&hdr_csum.to_be_bytes());

    let l4 = &mut pkt[ihl..ip_len];
    if proto == 6 && l4.len() >= 20 {
        let csum = l4_checksum_v4(src_ip, dst_ip, 6, l4, 16);
        l4[16..18].copy_from_slice(&csum.to_be_bytes());
    } else if proto == 17 && l4.len() >= 8 {
        let csum = l4_checksum_v4(src_ip, dst_ip, 17, l4, 6);
        l4[6..8].copy_from_slice(&csum.to_be_bytes());
    }
}

/// Recompute IPv6 TCP/UDP/ICMPv6 checksum
pub fn recompute_ipv6_checksums(pkt: &mut [u8]) {
    if pkt.len() < 40 || (pkt[0] >> 4) != 6 {
        return;
    }
    let next_hdr = pkt[6];
    let payload_len = (u16::from_be_bytes([pkt[4], pkt[5]]) as usize).min(pkt.len() - 40);
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    src_ip.copy_from_slice(&pkt[8..24]);
    dst_ip.copy_from_slice(&pkt[24..40]);

    let l4 = &mut pkt[40..40 + payload_len];
    if next_hdr == 6 && l4.len() >= 20 {
        let csum = l4_checksum_v6(&src_ip, &dst_ip, 6, l4, 16);
        l4[16..18].copy_from_slice(&csum.to_be_bytes());
    } else if next_hdr == 17 && l4.len() >= 8 {
        let csum = l4_checksum_v6(&src_ip, &dst_ip, 17, l4, 6);
        l4[6..8].copy_from_slice(&csum.to_be_bytes());
    } else if next_hdr == 58 && l4.len() >= 8 {
        let csum = l4_checksum_v6(&src_ip, &dst_ip, 58, l4, 2);
        l4[2..4].copy_from_slice(&csum.to_be_bytes());
    }
}

/// Wrap a raw UDP payload (e.g. WARP WireGuard packet) in a 28-byte IPv4 + UDP header for tunneling over VPN1
pub fn wrap_ipv4_udp(
    payload: &[u8],
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    ip_id: u16,
    out: &mut [u8],
) -> usize {
    let total_len = 28 + payload.len();
    let udp_len = (8 + payload.len()) as u16;
    out[0] = 0x45;
    out[1] = 0x00;
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    out[4..6].copy_from_slice(&ip_id.to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    out[8] = 64; // TTL
    out[9] = 17; // UDP
    out[10..12].copy_from_slice(&[0, 0]);
    out[12..16].copy_from_slice(&src_ip.octets());
    out[16..20].copy_from_slice(&dst_ip.octets());

    out[20..22].copy_from_slice(&src_port.to_be_bytes());
    out[22..24].copy_from_slice(&dst_port.to_be_bytes());
    out[24..26].copy_from_slice(&udp_len.to_be_bytes());
    out[26..28].copy_from_slice(&[0, 0]);
    out[28..total_len].copy_from_slice(payload);

    recompute_ipv4_checksums(&mut out[..total_len]);
    total_len
}

/// Extract inner UDP payload if `ip_pkt` is an IPv4 UDP packet destined to `expected_dst_port`
pub fn unwrap_ipv4_udp(ip_pkt: &[u8], expected_dst_port: u16) -> Option<&[u8]> {
    if ip_pkt.len() < 28 || (ip_pkt[0] >> 4) != 4 || ip_pkt[9] != 17 {
        return None;
    }
    let ihl = ((ip_pkt[0] & 0x0f) as usize) * 4;
    if ip_pkt.len() < ihl + 8 {
        return None;
    }
    let dst_port = u16::from_be_bytes([ip_pkt[ihl + 2], ip_pkt[ihl + 3]]);
    if dst_port != expected_dst_port {
        return None;
    }
    let udp_len = u16::from_be_bytes([ip_pkt[ihl + 4], ip_pkt[ihl + 5]]) as usize;
    if udp_len < 8 || ip_pkt.len() < ihl + udp_len {
        return None;
    }
    Some(&ip_pkt[ihl + 8..ihl + udp_len])
}

#[derive(Clone, Copy)]
struct NatEntry {
    orig_local_ip: Ipv4Addr,
    orig_remote_ip: Ipv4Addr,
    last_seen: Instant,
}

/// Bounded O(1) L3 Address & DNS Translator for TUN <-> WireGuard/WARP
pub struct L3NatTable {
    entries: HashMap<(u8, u16, Ipv4Addr, u16), NatEntry>,
    default_local_v4: Ipv4Addr,
    default_local_v6: Option<Ipv6Addr>,
    dns_override_v4: Option<Ipv4Addr>,
}

impl L3NatTable {
    pub fn new(host_local_v4: Ipv4Addr, dns_override_v4: Option<Ipv4Addr>) -> Self {
        Self {
            entries: HashMap::with_capacity(512),
            default_local_v4: host_local_v4,
            default_local_v6: None,
            dns_override_v4,
        }
    }

    /// Translate an outbound IP packet from `chain0` before encrypting into WireGuard/WARP
    pub fn translate_outbound(
        &mut self,
        pkt: &mut [u8],
        tunnel_v4: Ipv4Addr,
        tunnel_v6: Option<Ipv6Addr>,
        max_mss: u16,
    ) -> bool {
        if pkt.is_empty() {
            return false;
        }
        clamp_tcp_mss(pkt, max_mss);

        let version = pkt[0] >> 4;
        if version == 4 {
            if pkt.len() < 20 {
                return false;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if pkt.len() < ihl {
                return false;
            }
            let proto = pkt[9];
            let orig_src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let orig_dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            if orig_src.octets()[0..3] != [172, 31, 255] && !orig_src.is_loopback() {
                self.default_local_v4 = orig_src;
            }

            let mut actual_dst = orig_dst;
            if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4 {
                let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);

                if dst_port == 53 {
                    if let Some(dns_ip) = self.dns_override_v4 {
                        actual_dst = dns_ip;
                    }
                }

                if self.entries.len() >= 4096 {
                    let cutoff = Instant::now() - Duration::from_secs(60);
                    self.entries.retain(|_, v| v.last_seen > cutoff);
                    if self.entries.len() >= 4096 {
                        self.entries.clear();
                    }
                }

                self.entries.insert(
                    (proto, src_port, actual_dst, dst_port),
                    NatEntry {
                        orig_local_ip: orig_src,
                        orig_remote_ip: orig_dst,
                        last_seen: Instant::now(),
                    },
                );
            }

            pkt[12..16].copy_from_slice(&tunnel_v4.octets());
            pkt[16..20].copy_from_slice(&actual_dst.octets());
            recompute_ipv4_checksums(pkt);
            true
        } else if version == 6 {
            let Some(tun_v6) = tunnel_v6 else {
                return false;
            };
            if pkt.len() < 40 {
                return false;
            }
            let mut orig_v6 = [0u8; 16];
            orig_v6.copy_from_slice(&pkt[8..24]);
            self.default_local_v6 = Some(Ipv6Addr::from(orig_v6));
            pkt[8..24].copy_from_slice(&tun_v6.octets());
            recompute_ipv6_checksums(pkt);
            true
        } else {
            false
        }
    }

    /// Translate an inbound decrypted IP packet from WireGuard/WARP before writing to `chain0`
    pub fn translate_inbound(&mut self, pkt: &mut [u8], max_mss: u16) -> bool {
        if pkt.is_empty() {
            return false;
        }
        clamp_tcp_mss(pkt, max_mss);

        let version = pkt[0] >> 4;
        if version == 4 {
            if pkt.len() < 20 {
                return false;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if pkt.len() < ihl {
                return false;
            }
            let proto = pkt[9];
            let remote_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);

            let (target_local, target_remote) = if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4
            {
                let remote_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let local_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                if let Some(entry) = self
                    .entries
                    .get_mut(&(proto, local_port, remote_ip, remote_port))
                {
                    entry.last_seen = Instant::now();
                    (entry.orig_local_ip, entry.orig_remote_ip)
                } else {
                    (self.default_local_v4, remote_ip)
                }
            } else {
                (self.default_local_v4, remote_ip)
            };

            pkt[12..16].copy_from_slice(&target_remote.octets());
            pkt[16..20].copy_from_slice(&target_local.octets());
            recompute_ipv4_checksums(pkt);
            true
        } else if version == 6 {
            let Some(local_v6) = self.default_local_v6 else {
                return false;
            };
            if pkt.len() < 40 {
                return false;
            }
            pkt[24..40].copy_from_slice(&local_v6.octets());
            recompute_ipv6_checksums(pkt);
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Zero-Netstack L3 TCP Micro-Probe for Cloudflare /cdn-cgi/trace
// ============================================================================

pub struct TcpMicroProbe {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub client_seq: u32,
    pub server_seq: u32,
    pub request_sent: bool,
    pub response_buf: Vec<u8>,
}

impl TcpMicroProbe {
    pub fn new(local_ip: Ipv4Addr, local_port: u16, remote_ip: Ipv4Addr) -> Self {
        Self {
            local_ip,
            local_port,
            remote_ip,
            remote_port: 80,
            client_seq: 0x2468_ace0 ^ ((local_port as u32) << 16),
            server_seq: 0,
            request_sent: false,
            response_buf: Vec::with_capacity(512),
        }
    }

    /// Build 44-byte IPv4 + TCP SYN packet with MSS 1200
    pub fn build_syn(&self, out: &mut [u8]) -> usize {
        out[0..44].fill(0);
        out[0] = 0x45;
        out[2..4].copy_from_slice(&44u16.to_be_bytes());
        out[4..6].copy_from_slice(&0x1337u16.to_be_bytes());
        out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        out[8] = 64;
        out[9] = 6; // TCP
        out[12..16].copy_from_slice(&self.local_ip.octets());
        out[16..20].copy_from_slice(&self.remote_ip.octets());

        // TCP Header (24 bytes with 4-byte MSS option)
        out[20..22].copy_from_slice(&self.local_port.to_be_bytes());
        out[22..24].copy_from_slice(&self.remote_port.to_be_bytes());
        out[24..28].copy_from_slice(&self.client_seq.to_be_bytes());
        out[32] = 6 << 4; // Data offset = 6 (24 bytes)
        out[33] = 0x02; // SYN
        out[34..36].copy_from_slice(&65535u16.to_be_bytes());
        // MSS Option: Kind=2, Len=4, MSS=1200
        out[40] = 2;
        out[41] = 4;
        out[42..44].copy_from_slice(&1200u16.to_be_bytes());

        recompute_ipv4_checksums(&mut out[..44]);
        44
    }

    /// Inspect an incoming decrypted IPv4 packet; if it belongs to this probe, advance state
    /// and optionally write a reply TCP packet into `reply_out`. Returns `Some(trace_body)` when complete.
    pub fn on_packet(&mut self, pkt: &[u8], reply_out: &mut [u8]) -> (usize, Option<String>) {
        if pkt.len() < 40 || (pkt[0] >> 4) != 4 || pkt[9] != 6 {
            return (0, None);
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if pkt.len() < ihl + 20 {
            return (0, None);
        }
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);

        if dst_port != self.local_port || src_port != self.remote_port || src_ip != self.remote_ip {
            return (0, None);
        }

        let seq = u32::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7]]);
        let flags = pkt[ihl + 13];
        let data_offset = ((pkt[ihl + 12] >> 4) as usize) * 4;
        let ip_len = (u16::from_be_bytes([pkt[2], pkt[3]]) as usize).min(pkt.len());

        // Case 1: SYN-ACK received -> send ACK + HTTP GET /cdn-cgi/trace
        if (flags & 0x12) == 0x12 && !self.request_sent {
            self.client_seq = self.client_seq.wrapping_add(1);
            self.server_seq = seq.wrapping_add(1);
            self.request_sent = true;

            let http_req = b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            let total_len = 40 + http_req.len();
            reply_out[..total_len].fill(0);
            reply_out[0] = 0x45;
            reply_out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            reply_out[4..6].copy_from_slice(&0x1338u16.to_be_bytes());
            reply_out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
            reply_out[8] = 64;
            reply_out[9] = 6;
            reply_out[12..16].copy_from_slice(&self.local_ip.octets());
            reply_out[16..20].copy_from_slice(&self.remote_ip.octets());

            reply_out[20..22].copy_from_slice(&self.local_port.to_be_bytes());
            reply_out[22..24].copy_from_slice(&self.remote_port.to_be_bytes());
            reply_out[24..28].copy_from_slice(&self.client_seq.to_be_bytes());
            reply_out[28..32].copy_from_slice(&self.server_seq.to_be_bytes());
            reply_out[32] = 5 << 4;
            reply_out[33] = 0x18; // PSH | ACK
            reply_out[34..36].copy_from_slice(&65535u16.to_be_bytes());
            reply_out[40..total_len].copy_from_slice(http_req);

            self.client_seq = self.client_seq.wrapping_add(http_req.len() as u32);
            recompute_ipv4_checksums(&mut reply_out[..total_len]);
            return (total_len, None);
        }

        // Case 2: Data payload received
        if ip_len > ihl + data_offset {
            let payload = &pkt[ihl + data_offset..ip_len];
            self.response_buf.extend_from_slice(payload);
            self.server_seq = seq.wrapping_add(payload.len() as u32);
            if (flags & 0x01) != 0 {
                self.server_seq = self.server_seq.wrapping_add(1);
            }

            let text = String::from_utf8_lossy(&self.response_buf);
            if let Some(pos) = text.find("\r\n\r\n") {
                let body = &text[pos + 4..];
                if body.contains("ip=") && body.contains("warp=") {
                    // Send RST|ACK to cleanly close server state
                    reply_out[..40].fill(0);
                    reply_out[0] = 0x45;
                    reply_out[2..4].copy_from_slice(&40u16.to_be_bytes());
                    reply_out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
                    reply_out[8] = 64;
                    reply_out[9] = 6;
                    reply_out[12..16].copy_from_slice(&self.local_ip.octets());
                    reply_out[16..20].copy_from_slice(&self.remote_ip.octets());
                    reply_out[20..22].copy_from_slice(&self.local_port.to_be_bytes());
                    reply_out[22..24].copy_from_slice(&self.remote_port.to_be_bytes());
                    reply_out[24..28].copy_from_slice(&self.client_seq.to_be_bytes());
                    reply_out[28..32].copy_from_slice(&self.server_seq.to_be_bytes());
                    reply_out[32] = 5 << 4;
                    reply_out[33] = 0x14; // RST | ACK
                    recompute_ipv4_checksums(&mut reply_out[..40]);

                    return (40, Some(body.trim().to_string()));
                }
            }
        }

        (0, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap_ipv4_udp_and_mss_clamping() {
        let mut out = [0u8; 128];
        let payload = b"hello-warp-wireguard";
        let len = wrap_ipv4_udp(
            payload,
            Ipv4Addr::new(10, 2, 0, 2),
            51821,
            Ipv4Addr::new(162, 159, 192, 1),
            2408,
            42,
            &mut out,
        );
        assert_eq!(len, 28 + payload.len());
        let unwrapped = unwrap_ipv4_udp(&out[..len], 2408).expect("Should unwrap UDP");
        assert_eq!(unwrapped, payload);

        // Test TCP SYN MSS clamping
        let probe = TcpMicroProbe::new(
            Ipv4Addr::new(172, 16, 0, 2),
            55000,
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let mut syn = [0u8; 64];
        let syn_len = probe.build_syn(&mut syn);
        // Set MSS to 1460 initially
        syn[42..44].copy_from_slice(&1460u16.to_be_bytes());
        clamp_tcp_mss(&mut syn[..syn_len], 1200);
        assert_eq!(u16::from_be_bytes([syn[42], syn[43]]), 1200);
    }

    #[test]
    fn test_l3_nat_table_roundtrip() {
        let mut nat = L3NatTable::new(
            Ipv4Addr::new(10, 82, 160, 174),
            Some(Ipv4Addr::new(1, 1, 1, 1)),
        );
        let mut pkt = [0u8; 64];
        let len = wrap_ipv4_udp(
            b"dns-query",
            Ipv4Addr::new(10, 82, 160, 174),
            53210,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            1,
            &mut pkt,
        );

        assert!(nat.translate_outbound(
            &mut pkt[..len],
            Ipv4Addr::new(172, 16, 0, 2),
            None,
            1200
        ));
        // Source should be translated to WARP IP 172.16.0.2, DNS dst overridden to 1.1.1.1
        assert_eq!(&pkt[12..16], &[172, 16, 0, 2]);
        assert_eq!(&pkt[16..20], &[1, 1, 1, 1]);

        // Simulate reply from 1.1.1.1:53 to 172.16.0.2:53210
        let mut reply = [0u8; 64];
        let rlen = wrap_ipv4_udp(
            b"dns-ans",
            Ipv4Addr::new(1, 1, 1, 1),
            53,
            Ipv4Addr::new(172, 16, 0, 2),
            53210,
            2,
            &mut reply,
        );
        assert!(nat.translate_inbound(&mut reply[..rlen], 1200));
        // Source restored to 8.8.8.8, dest restored to 10.82.160.174
        assert_eq!(&reply[12..16], &[8, 8, 8, 8]);
        assert_eq!(&reply[16..20], &[10, 82, 160, 174]);
    }
}
