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
    let ip_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if ihl < 20 || ip_len < ihl || ip_len > pkt.len() {
        return;
    }
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
    // Leave flags/fragment offset at 0x0000 (clear DF) so outer WG peer never drops inner WARP frames
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
    port_owner: HashMap<(u8, u16), Ipv4Addr>,
    default_local_v4: Ipv4Addr,
    default_local_v6: Option<Ipv6Addr>,
    dns_override_v4: Option<Ipv4Addr>,
    last_prune: Instant,
}

impl L3NatTable {
    pub fn new(host_local_v4: Ipv4Addr, dns_override_v4: Option<Ipv4Addr>) -> Self {
        Self {
            entries: HashMap::with_capacity(1024),
            port_owner: HashMap::with_capacity(1024),
            default_local_v4: host_local_v4,
            default_local_v6: None,
            dns_override_v4,
            last_prune: Instant::now(),
        }
    }

    fn maybe_prune(&mut self, now: Instant) {
        if now.duration_since(self.last_prune) < Duration::from_secs(10) {
            return;
        }
        self.last_prune = now;
        let tcp_cut = now.checked_sub(Duration::from_secs(240)).unwrap_or(now);
        let udp_cut = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        self.entries.retain(|&(proto, _, _, _), v| {
            v.last_seen > if proto == 6 { tcp_cut } else { udp_cut }
        });
        // Table pressure must not invalidate live TCP mappings or DNS destination translations.
        if self.entries.capacity() > 2048 && self.entries.len() <= 1024 {
            self.entries.shrink_to(1024);
        }
        self.port_owner.clear();
        for (&(proto, port, _, _), entry) in &self.entries {
            self.port_owner.insert((proto, port), entry.orig_local_ip);
        }
        if self.port_owner.capacity() > 2048 && self.port_owner.len() <= 1024 {
            self.port_owner.shrink_to(1024);
        }
    }

    pub fn translate_outbound(&mut self, pkt: &mut [u8], tun_v4: Ipv4Addr, tun_v6: Option<Ipv6Addr>, max_mss: u16) -> bool {
        if pkt.is_empty() { return false; }
        clamp_tcp_mss(pkt, max_mss);
        match pkt[0] >> 4 {
            4 => {
                let ihl = ((pkt[0] & 0x0f) as usize) * 4;
                if ihl < 20 || pkt.len() < ihl || pkt[8] <= 1 {
                    return false;
                }
                let ip_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
                if ip_len < ihl || ip_len > pkt.len() {
                    return false;
                }
                let proto = pkt[9];
                let orig_src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let orig_dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                if orig_dst.is_loopback()
                    || orig_dst.is_multicast()
                    || orig_dst.is_broadcast()
                    || orig_dst.is_unspecified()
                    || orig_dst == tun_v4
                {
                    return false;
                }
                if !orig_src.is_loopback()
                    && !orig_src.is_unspecified()
                    && orig_src != tun_v4
                    && orig_src != Ipv4Addr::new(172, 31, 255, 1)
                {
                    self.default_local_v4 = orig_src;
                }
                let now = Instant::now();
                let mut actual_dst = orig_dst;
                if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4 {
                    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                    if dport == 53 {
                        if let Some(dns) = self.dns_override_v4 {
                            let is_standard_public = matches!(
                                orig_dst.octets(),
                                [8, 8, 8, 8] | [8, 8, 4, 4] | [1, 1, 1, 1] | [1, 0, 0, 1]
                            );
                            let is_custom_override = !matches!(
                                dns.octets(),
                                [8, 8, 8, 8] | [8, 8, 4, 4] | [1, 1, 1, 1] | [1, 0, 0, 1]
                            );
                            if is_custom_override || !is_standard_public {
                                actual_dst = dns;
                            }
                        }
                    }
                    self.maybe_prune(now);
                    self.port_owner.insert((proto, sport), orig_src);
                    self.entries.insert(
                        (proto, sport, actual_dst, dport),
                        NatEntry { orig_local_ip: orig_src, orig_remote_ip: orig_dst, last_seen: now },
                    );
                } else if proto == 1 && pkt.len() >= ihl + 8 {
                    let icmp_id = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]);
                    self.maybe_prune(now);
                    self.port_owner.insert((1, icmp_id), orig_src);
                    self.entries.insert(
                        (1, icmp_id, actual_dst, 0),
                        NatEntry { orig_local_ip: orig_src, orig_remote_ip: orig_dst, last_seen: now },
                    );
                }
                pkt[12..16].copy_from_slice(&tun_v4.octets());
                pkt[16..20].copy_from_slice(&actual_dst.octets());
                recompute_ipv4_checksums(pkt);
                true
            }
            6 => {
                let Some(v6) = tun_v6.filter(|_| pkt.len() >= 40 && pkt[7] > 1) else { return false };
                let dst_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
                if dst_v6.is_loopback() || dst_v6.is_multicast() || dst_v6.is_unspecified() || dst_v6 == v6 {
                    return false;
                }
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
                if ihl < 20 || pkt.len() < ihl {
                    return false;
                }
                let ip_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
                if ip_len < ihl || ip_len > pkt.len() {
                    return false;
                }
                let proto = pkt[9];
                let remote_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let (t_local, t_remote) = if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4 {
                    let rport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                    let lport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                    if let Some(e) = self.entries.get_mut(&(proto, lport, remote_ip, rport)) {
                        e.last_seen = Instant::now();
                        (e.orig_local_ip, e.orig_remote_ip)
                    } else {
                        let local_ip = self.port_owner.get(&(proto, lport)).copied().unwrap_or(self.default_local_v4);
                        (local_ip, remote_ip)
                    }
                } else if proto == 1 && pkt.len() >= ihl + 8 {
                    let icmp_id = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]);
                    if let Some(e) = self.entries.get_mut(&(1, icmp_id, remote_ip, 0)) {
                        e.last_seen = Instant::now();
                        (e.orig_local_ip, e.orig_remote_ip)
                    } else {
                        let local_ip = self.port_owner.get(&(1, icmp_id)).copied().unwrap_or(self.default_local_v4);
                        (local_ip, remote_ip)
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

pub fn encode_dns_a_query(domain: &str, tx_id: u16, out: &mut [u8]) -> Option<usize> {
    let clean = domain.trim().trim_end_matches('.');
    if clean.is_empty() || clean.len() > 253 || out.len() < 300 {
        return None;
    }
    out[0..12].fill(0);
    out[0..2].copy_from_slice(&tx_id.to_be_bytes());
    out[2] = 0x01; // RD = 1
    out[5] = 0x01; // QDCOUNT = 1
    let mut pos = 12;
    for label in clean.split('.') {
        let lb = label.as_bytes();
        if lb.is_empty() || lb.len() > 63 || pos + 1 + lb.len() + 5 > out.len() {
            return None;
        }
        out[pos] = lb.len() as u8;
        out[pos + 1..pos + 1 + lb.len()].copy_from_slice(lb);
        pos += 1 + lb.len();
    }
    out[pos] = 0;
    out[pos + 1..pos + 5].copy_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    Some(pos + 5)
}

fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        if pos >= pkt.len() || jumps > 16 {
            return None;
        }
        let b = pkt[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if (b & 0xC0) == 0xC0 {
            return (pos + 2 <= pkt.len()).then_some(pos + 2);
        }
        if (b & 0xC0) != 0 {
            return None;
        }
        pos += 1 + (b as usize);
        jumps += 1;
    }
}

pub fn parse_dns_a_response(pkt: &[u8], expected_tx_id: u16) -> Vec<Ipv4Addr> {
    let mut addrs = Vec::new();
    if pkt.len() < 12 {
        return addrs;
    }
    if u16::from_be_bytes([pkt[0], pkt[1]]) != expected_tx_id
        || (pkt[2] & 0x80) == 0
        || (pkt[3] & 0x0f) != 0
    {
        return addrs;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        let Some(next) = skip_dns_name(pkt, pos) else { return addrs };
        if next + 4 > pkt.len() {
            return addrs;
        }
        pos = next + 4;
    }
    for _ in 0..ancount {
        let Some(next) = skip_dns_name(pkt, pos) else { break };
        if next + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[next], pkt[next + 1]]);
        let rclass = u16::from_be_bytes([pkt[next + 2], pkt[next + 3]]);
        let rdlen = u16::from_be_bytes([pkt[next + 8], pkt[next + 9]]) as usize;
        let rdata_start = next + 10;
        if rdata_start + rdlen > pkt.len() {
            break;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            let ip = Ipv4Addr::new(
                pkt[rdata_start],
                pkt[rdata_start + 1],
                pkt[rdata_start + 2],
                pkt[rdata_start + 3],
            );
            if !ip.is_unspecified() && !ip.is_loopback() && !addrs.contains(&ip) {
                addrs.push(ip);
            }
        }
        pos = rdata_start + rdlen;
    }
    addrs
}

pub fn inspect_dns_question(pkt: &[u8]) -> Option<(String, u16)> {
    if pkt.len() < 17 || u16::from_be_bytes([pkt[4], pkt[5]]) == 0 {
        return None;
    }
    let mut pos = 12;
    let mut domain = String::with_capacity(64);
    loop {
        if pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) != 0 || pos + 1 + len > pkt.len() || domain.len() + len > 253 {
            return None;
        }
        if !domain.is_empty() {
            domain.push('.');
        }
        let label = std::str::from_utf8(&pkt[pos + 1..pos + 1 + len]).ok()?;
        domain.push_str(&label.to_ascii_lowercase());
        pos += 1 + len;
    }
    if pos + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    Some((domain, qtype))
}

pub fn build_empty_noerror_dns_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 17 {
        return None;
    }
    let next = skip_dns_name(query, 12)?;
    if next + 4 > query.len() {
        return None;
    }
    let mut resp = query[..next + 4].to_vec();
    resp[2] = 0x81; // QR=1, RD=1
    resp[3] = 0x80; // RA=1, RCODE=0 (NOERROR)
    resp[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp[6..12].fill(0); // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    Some(resp)
}

pub fn build_cached_a_dns_response(query: &[u8], ips: &[Ipv4Addr]) -> Option<Vec<u8>> {
    if query.len() < 17 || ips.is_empty() {
        return None;
    }
    let next = skip_dns_name(query, 12)?;
    if next + 4 > query.len() {
        return None;
    }
    let count = ips.len().min(8);
    let mut resp = Vec::with_capacity(next + 4 + count * 16);
    resp.extend_from_slice(&query[..next + 4]);
    resp[2] = 0x81; // QR=1, RD=1
    resp[3] = 0x80; // RA=1, RCODE=0 (NOERROR)
    resp[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp[6..8].copy_from_slice(&(count as u16).to_be_bytes()); // ANCOUNT=count
    resp[8..12].fill(0); // NSCOUNT=0, ARCOUNT=0
    for ip in ips.iter().take(count) {
        resp.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to offset 12
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE = A (1)
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN (1)
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        resp.extend_from_slice(&ip.octets());
    }
    Some(resp)
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

    fn write_tcp_pkt_seq(&self, seq: u32, flags: u8, opts: &[u8], payload: &[u8], out: &mut [u8]) -> usize {
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
        out[24..28].copy_from_slice(&seq.to_be_bytes());
        out[28..32].copy_from_slice(&self.server_seq.to_be_bytes());
        out[32] = ((tcp_hdr_len / 4) as u8) << 4;
        out[33] = flags;
        out[34..36].copy_from_slice(&65535u16.to_be_bytes());
        out[40..40 + opts.len()].copy_from_slice(opts);
        out[40 + opts.len()..total_len].copy_from_slice(payload);
        recompute_ipv4_checksums(&mut out[..total_len]);
        total_len
    }

    fn write_tcp_pkt(&self, flags: u8, opts: &[u8], payload: &[u8], out: &mut [u8]) -> usize {
        self.write_tcp_pkt_seq(self.client_seq, flags, opts, payload, out)
    }

    pub fn build_syn(&self, out: &mut [u8]) -> usize {
        self.write_tcp_pkt(0x02, &[2, 4, 0x04, 0x60], &[], out)
    }

    pub fn retransmit_request(&self, out: &mut [u8]) -> usize {
        let req = b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        self.write_tcp_pkt_seq(self.client_seq.wrapping_sub(req.len() as u32), 0x18, &[], req, out)
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

        if (flags & 0x12) == 0x12 {
            if !self.request_sent {
                self.client_seq = self.client_seq.wrapping_add(1);
                self.server_seq = seq.wrapping_add(1);
                self.request_sent = true;
                let req = b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
                let len = self.write_tcp_pkt(0x18, &[], req, reply_out);
                self.client_seq = self.client_seq.wrapping_add(req.len() as u32);
                return (len, None);
            } else {
                return (self.retransmit_request(reply_out), None);
            }
        }
        if ip_len > ihl + doff {
            let payload = &pkt[ihl + doff..ip_len];
            if seq == self.server_seq {
                self.response_buf.extend_from_slice(payload);
                self.server_seq = seq.wrapping_add(payload.len() as u32 + ((flags & 1) as u32));
            }
            let text = String::from_utf8_lossy(&self.response_buf);
            if let Some(pos) = text.find("\r\n\r\n") {
                let body = &text[pos + 4..];
                if body.contains("ip=") && body.contains("warp=") {
                    let len = self.write_tcp_pkt(0x14, &[], &[], reply_out);
                    return (len, Some(body.trim().to_string()));
                }
            }
            let ack_len = self.write_tcp_pkt(0x10, &[], &[], reply_out);
            return (ack_len, None);
        } else if (flags & 0x01) != 0 && seq == self.server_seq {
            self.server_seq = self.server_seq.wrapping_add(1);
            let ack_len = self.write_tcp_pkt(0x10, &[], &[], reply_out);
            return (ack_len, None);
        }
        (0, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_preserves_idle_tcp_mappings_under_load() {
        let mut nat = L3NatTable::new(Ipv4Addr::LOCALHOST, None);
        let now = Instant::now();
        let local = Ipv4Addr::new(172, 31, 255, 1);
        let remote = Ipv4Addr::new(93, 184, 216, 34);
        for port in 10000..13000 {
            nat.entries.insert(
                (6, port, remote, 443),
                NatEntry {
                    orig_local_ip: local,
                    orig_remote_ip: remote,
                    last_seen: now - Duration::from_secs(30),
                },
            );
            nat.port_owner.insert((6, port), local);
        }
        nat.last_prune = now - Duration::from_secs(11);
        nat.maybe_prune(now);
        assert_eq!(nat.entries.len(), 3000);
        assert_eq!(nat.port_owner.len(), 3000);
        nat.maybe_prune(now + Duration::from_secs(241));
        assert!(nat.entries.is_empty());
        assert!(nat.port_owner.is_empty());
    }

    #[test]
    fn pruning_cleans_small_tables_and_malformed_ipv4_is_rejected() {
        let mut nat = L3NatTable::new(Ipv4Addr::LOCALHOST, None);
        let mut pkt = [0u8; 64];
        let len = wrap_ipv4_udp(
            b"test",
            Ipv4Addr::LOCALHOST,
            1234,
            Ipv4Addr::new(1, 1, 1, 1),
            53,
            1,
            &mut pkt,
        );
        assert!(nat.translate_outbound(&mut pkt[..len], Ipv4Addr::new(10, 0, 0, 2), None, 1120));
        nat.maybe_prune(Instant::now() + Duration::from_secs(61));
        assert!(nat.entries.is_empty());
        assert!(nat.port_owner.is_empty());
        for (ihl, ip_len) in [(4, 32), (15, 20), (5, 65)] {
            pkt[0] = 0x40 | ihl;
            pkt[2..4].copy_from_slice(&u16::to_be_bytes(ip_len));
            recompute_ipv4_checksums(&mut pkt);
            assert!(!nat.translate_outbound(&mut pkt, Ipv4Addr::new(10, 0, 0, 2), None, 1120));
            assert!(!nat.translate_inbound(&mut pkt, 1120));
        }
    }

    #[test]
    fn test_dns_a_codec_and_l3_nat_port_owner_preservation() {
        let mut qbuf = [0u8; 512];
        let qlen = encode_dns_a_query("www.Google.com", 0x1234, &mut qbuf).unwrap();
        assert!(qlen > 16);
        assert_eq!(
            inspect_dns_question(&qbuf[..qlen]),
            Some(("www.google.com".to_string(), 1))
        );

        let empty_resp = build_empty_noerror_dns_response(&qbuf[..qlen]).unwrap();
        assert_eq!(parse_dns_a_response(&empty_resp, 0x1234), Vec::<Ipv4Addr>::new());

        let cached_resp =
            build_cached_a_dns_response(&qbuf[..qlen], &[Ipv4Addr::new(142, 250, 190, 36)]).unwrap();
        let ips = parse_dns_a_response(&cached_resp, 0x1234);
        assert_eq!(ips, vec![Ipv4Addr::new(142, 250, 190, 36)]);

        // Test L3NatTable preserves TUN_IPV4 (172.31.255.1) and host_ipv4 (10.12.144.106) per-port
        let mut nat = L3NatTable::new(Ipv4Addr::new(10, 12, 144, 106), Some(Ipv4Addr::new(8, 8, 8, 8)));
        let mut pkt = [0u8; 64];
        let len = wrap_ipv4_udp(
            b"ping",
            Ipv4Addr::new(172, 31, 255, 1),
            55000,
            Ipv4Addr::new(93, 184, 216, 34),
            443,
            1,
            &mut pkt,
        );
        // Verify inner wrap_ipv4_udp cleared DF bit
        assert_eq!(&pkt[6..8], &[0, 0]);
        assert!(nat.translate_outbound(&mut pkt[..len], Ipv4Addr::new(172, 16, 0, 2), None, 1120));
        assert_eq!(&pkt[12..16], &[172, 16, 0, 2]);

        // Simulate inbound response even if 4-tuple entry was evicted (port_owner fallback)
        nat.entries.clear();
        let mut reply = [0u8; 64];
        let rlen = wrap_ipv4_udp(
            b"pong",
            Ipv4Addr::new(93, 184, 216, 34),
            443,
            Ipv4Addr::new(172, 16, 0, 2),
            55000,
            2,
            &mut reply,
        );
        assert!(nat.translate_inbound(&mut reply[..rlen], 1120));
        assert_eq!(&reply[16..20], &[172, 31, 255, 1]);
        // Verify default_local_v4 was NOT overwritten by 172.31.255.1
        assert_eq!(nat.default_local_v4, Ipv4Addr::new(10, 12, 144, 106));
    }
}
