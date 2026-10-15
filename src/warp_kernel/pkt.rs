use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[inline]
fn fold_csum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[inline]
fn sum_slice(mut sum: u32, data: &[u8], skip_offset: usize) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        if i != skip_offset {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        }
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

#[inline]
pub fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    fold_csum(sum_slice(0, &hdr[..(hdr.len() & !1)], 10))
}

#[inline]
fn l4_checksum_v4(src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8, l4: &[u8], skip: usize) -> u16 {
    let mut sum = sum_slice(0, &src_ip, usize::MAX);
    sum = sum_slice(sum, &dst_ip, usize::MAX);
    sum += (proto as u32) + (l4.len() as u32);
    let res = fold_csum(sum_slice(sum, l4, skip));
    if proto == 17 && res == 0 { 0xffff } else { res }
}

#[inline]
fn l4_checksum_v6(src_ip: &[u8; 16], dst_ip: &[u8; 16], next_hdr: u8, l4: &[u8], skip: usize) -> u16 {
    let mut sum = sum_slice(0, src_ip, usize::MAX);
    sum = sum_slice(sum, dst_ip, usize::MAX);
    let len = l4.len() as u32;
    sum += (len >> 16) + (len & 0xffff) + (next_hdr as u32);
    let res = fold_csum(sum_slice(sum, l4, skip));
    if next_hdr == 17 && res == 0 { 0xffff } else { res }
}

pub fn clamp_tcp_mss(pkt: &mut [u8], max_mss: u16) {
    if pkt.is_empty() { return; }
    let tcp_off = match pkt[0] >> 4 {
        4 if pkt.len() >= 40 && pkt[9] == 6 => ((pkt[0] & 0x0f) as usize) * 4,
        6 if pkt.len() >= 60 && pkt[6] == 6 => 40,
        _ => return,
    };
    if pkt.len() < tcp_off + 20 || (pkt[tcp_off + 13] & 0x02) == 0 {
        return;
    }
    let opts_end = (tcp_off + ((pkt[tcp_off + 12] >> 4) as usize) * 4).min(pkt.len());
    let mut idx = tcp_off + 20;
    while idx < opts_end {
        match pkt[idx] {
            0 => break,
            1 => idx += 1,
            kind => {
                if idx + 1 >= opts_end { break; }
                let olen = pkt[idx + 1] as usize;
                if olen < 2 || idx + olen > opts_end { break; }
                if kind == 2 && olen == 4 && u16::from_be_bytes([pkt[idx + 2], pkt[idx + 3]]) > max_mss {
                    pkt[idx + 2..idx + 4].copy_from_slice(&max_mss.to_be_bytes());
                    break;
                }
                idx += olen;
            }
        }
    }
}

pub fn recompute_ipv4_checksums(pkt: &mut [u8]) {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 { return; }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl { return; }
    let ip_len = (u16::from_be_bytes([pkt[2], pkt[3]]) as usize).min(pkt.len());
    let proto = pkt[9];
    let src: [u8; 4] = pkt[12..16].try_into().unwrap();
    let dst: [u8; 4] = pkt[16..20].try_into().unwrap();
    let hcsum = ipv4_header_checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&hcsum.to_be_bytes());
    let l4 = &mut pkt[ihl..ip_len];
    if proto == 6 && l4.len() >= 20 {
        let c = l4_checksum_v4(src, dst, 6, l4, 16);
        l4[16..18].copy_from_slice(&c.to_be_bytes());
    } else if proto == 17 && l4.len() >= 8 {
        let c = l4_checksum_v4(src, dst, 17, l4, 6);
        l4[6..8].copy_from_slice(&c.to_be_bytes());
    }
}

pub fn recompute_ipv6_checksums(pkt: &mut [u8]) {
    if pkt.len() < 40 || (pkt[0] >> 4) != 6 { return; }
    let nh = pkt[6];
    let plen = (u16::from_be_bytes([pkt[4], pkt[5]]) as usize).min(pkt.len() - 40);
    let src: [u8; 16] = pkt[8..24].try_into().unwrap();
    let dst: [u8; 16] = pkt[24..40].try_into().unwrap();
    let l4 = &mut pkt[40..40 + plen];
    let skip = match nh {
        6 if l4.len() >= 20 => Some(16),
        17 if l4.len() >= 8 => Some(6),
        58 if l4.len() >= 8 => Some(2),
        _ => None,
    };
    if let Some(off) = skip {
        let c = l4_checksum_v6(&src, &dst, nh, l4, off);
        l4[off..off + 2].copy_from_slice(&c.to_be_bytes());
    }
}

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
    out[0..28].fill(0);
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    out[4..6].copy_from_slice(&ip_id.to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    out[8] = 64;
    out[9] = 17;
    out[12..16].copy_from_slice(&src_ip.octets());
    out[16..20].copy_from_slice(&dst_ip.octets());
    out[20..22].copy_from_slice(&src_port.to_be_bytes());
    out[22..24].copy_from_slice(&dst_port.to_be_bytes());
    out[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    out[28..total_len].copy_from_slice(payload);
    recompute_ipv4_checksums(&mut out[..total_len]);
    total_len
}

pub fn unwrap_ipv4_udp(ip_pkt: &[u8], expected_dst_port: u16) -> Option<&[u8]> {
    if ip_pkt.len() < 28 || (ip_pkt[0] >> 4) != 4 || ip_pkt[9] != 17 { return None; }
    let ihl = ((ip_pkt[0] & 0x0f) as usize) * 4;
    if ip_pkt.len() < ihl + 8 { return None; }
    if u16::from_be_bytes([ip_pkt[ihl + 2], ip_pkt[ihl + 3]]) != expected_dst_port { return None; }
    let ulen = u16::from_be_bytes([ip_pkt[ihl + 4], ip_pkt[ihl + 5]]) as usize;
    (ulen >= 8 && ip_pkt.len() >= ihl + ulen).then(|| &ip_pkt[ihl + 8..ihl + ulen])
}

#[derive(Clone, Copy)]
struct NatEntry {
    orig_local_ip: Ipv4Addr,
    orig_remote_ip: Ipv4Addr,
    last_seen: Instant,
}

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

    pub fn translate_outbound(&mut self, pkt: &mut [u8], tun_v4: Ipv4Addr, tun_v6: Option<Ipv6Addr>, max_mss: u16) -> bool {
        if pkt.is_empty() { return false; }
        clamp_tcp_mss(pkt, max_mss);
        match pkt[0] >> 4 {
            4 => {
                let ihl = ((pkt[0] & 0x0f) as usize) * 4;
                if pkt.len() < ihl.max(20) { return false; }
                let proto = pkt[9];
                let orig_src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let orig_dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                if orig_src.octets()[0..3] != [172, 31, 255] && !orig_src.is_loopback() {
                    self.default_local_v4 = orig_src;
                }
                let mut actual_dst = orig_dst;
                if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4 {
                    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                    if dport == 53 {
                        if let Some(dns) = self.dns_override_v4 { actual_dst = dns; }
                    }
                    if self.entries.len() >= 4096 {
                        let cut = Instant::now() - Duration::from_secs(60);
                        self.entries.retain(|_, v| v.last_seen > cut);
                    }
                    self.entries.insert(
                        (proto, sport, actual_dst, dport),
                        NatEntry { orig_local_ip: orig_src, orig_remote_ip: orig_dst, last_seen: Instant::now() },
                    );
                }
                pkt[12..16].copy_from_slice(&tun_v4.octets());
                pkt[16..20].copy_from_slice(&actual_dst.octets());
                recompute_ipv4_checksums(pkt);
                true
            }
            6 => {
                let Some(v6) = tun_v6.filter(|_| pkt.len() >= 40) else { return false };
                self.default_local_v6 = Some(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap()));
                pkt[8..24].copy_from_slice(&v6.octets());
                recompute_ipv6_checksums(pkt);
                true
            }
            _ => false,
        }
    }

    pub fn translate_inbound(&mut self, pkt: &mut [u8], max_mss: u16) -> bool {
        if pkt.is_empty() { return false; }
        clamp_tcp_mss(pkt, max_mss);
        match pkt[0] >> 4 {
            4 => {
                let ihl = ((pkt[0] & 0x0f) as usize) * 4;
                if pkt.len() < ihl.max(20) { return false; }
                let proto = pkt[9];
                let remote_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let (t_local, t_remote) = if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4 {
                    let rport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                    let lport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                    if let Some(e) = self.entries.get_mut(&(proto, lport, remote_ip, rport)) {
                        e.last_seen = Instant::now();
                        (e.orig_local_ip, e.orig_remote_ip)
                    } else {
                        (self.default_local_v4, remote_ip)
                    }
                } else {
                    (self.default_local_v4, remote_ip)
                };
                pkt[12..16].copy_from_slice(&t_remote.octets());
                pkt[16..20].copy_from_slice(&t_local.octets());
                recompute_ipv4_checksums(pkt);
                true
            }
            6 => {
                let Some(lv6) = self.default_local_v6.filter(|_| pkt.len() >= 40) else { return false };
                pkt[24..40].copy_from_slice(&lv6.octets());
                recompute_ipv6_checksums(pkt);
                true
            }
            _ => false,
        }
    }
}

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

    fn write_tcp_pkt(&self, flags: u8, opts: &[u8], payload: &[u8], out: &mut [u8]) -> usize {
        let tcp_hdr_len = 20 + opts.len();
        let total_len = 20 + tcp_hdr_len + payload.len();
        out[..total_len].fill(0);
        out[0] = 0x45;
        out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        out[8] = 64;
        out[9] = 6;
        out[12..16].copy_from_slice(&self.local_ip.octets());
        out[16..20].copy_from_slice(&self.remote_ip.octets());
        out[20..22].copy_from_slice(&self.local_port.to_be_bytes());
        out[22..24].copy_from_slice(&self.remote_port.to_be_bytes());
        out[24..28].copy_from_slice(&self.client_seq.to_be_bytes());
        out[28..32].copy_from_slice(&self.server_seq.to_be_bytes());
        out[32] = ((tcp_hdr_len / 4) as u8) << 4;
        out[33] = flags;
        out[34..36].copy_from_slice(&65535u16.to_be_bytes());
        out[40..40 + opts.len()].copy_from_slice(opts);
        out[40 + opts.len()..total_len].copy_from_slice(payload);
        recompute_ipv4_checksums(&mut out[..total_len]);
        total_len
    }

    pub fn build_syn(&self, out: &mut [u8]) -> usize {
        self.write_tcp_pkt(0x02, &[2, 4, 0x04, 0xb0], &[], out)
    }

    pub fn on_packet(&mut self, pkt: &[u8], reply_out: &mut [u8]) -> (usize, Option<String>) {
        if pkt.len() < 40 || (pkt[0] >> 4) != 4 || pkt[9] != 6 { return (0, None); }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if pkt.len() < ihl + 20 { return (0, None); }
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        if dport != self.local_port || sport != self.remote_port || src_ip != self.remote_ip {
            return (0, None);
        }
        let seq = u32::from_be_bytes(pkt[ihl + 4..ihl + 8].try_into().unwrap());
        let flags = pkt[ihl + 13];
        let doff = ((pkt[ihl + 12] >> 4) as usize) * 4;
        let ip_len = (u16::from_be_bytes([pkt[2], pkt[3]]) as usize).min(pkt.len());

        if (flags & 0x12) == 0x12 && !self.request_sent {
            self.client_seq = self.client_seq.wrapping_add(1);
            self.server_seq = seq.wrapping_add(1);
            self.request_sent = true;
            let req = b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            let len = self.write_tcp_pkt(0x18, &[], req, reply_out);
            self.client_seq = self.client_seq.wrapping_add(req.len() as u32);
            return (len, None);
        }
        if ip_len > ihl + doff {
            let payload = &pkt[ihl + doff..ip_len];
            self.response_buf.extend_from_slice(payload);
            self.server_seq = seq.wrapping_add(payload.len() as u32 + ((flags & 1) as u32));
            let text = String::from_utf8_lossy(&self.response_buf);
            if let Some(pos) = text.find("\r\n\r\n") {
                let body = &text[pos + 4..];
                if body.contains("ip=") && body.contains("warp=") {
                    let len = self.write_tcp_pkt(0x14, &[], &[], reply_out);
                    return (len, Some(body.trim().to_string()));
                }
            }
        }
        (0, None)
    }
}
