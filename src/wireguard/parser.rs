use crate::error::{ChainError, Result};
use crate::wireguard::model::{WgConfig, WgEndpoint, WgInterface, WgPeer};
use base64::prelude::*;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

fn wg_err(section: &str, field: &str, msg: impl Into<String>) -> ChainError {
    ChainError::WgParseError {
        section: section.to_string(),
        field: field.to_string(),
        message: msg.into(),
    }
}

pub fn validate_base64_32_bytes(key: &str, section: &str, field: &str) -> Result<()> {
    let clean = key.trim();
    let bytes = BASE64_STANDARD
        .decode(clean.as_bytes())
        .map_err(|e| wg_err(section, field, format!("Invalid Base64: {}", e)))?;
    if clean.len() != 44 || bytes.len() != 32 {
        return Err(wg_err(section, field, "Key must decode to 32 bytes (44 Base64 chars)"));
    }
    Ok(())
}

pub fn parse_endpoint(raw: &str, section: &str, field: &str) -> Result<WgEndpoint> {
    let raw = raw.trim();
    let (host, port_str) = if let Some(rest) = raw.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| wg_err(section, field, "Malformed IPv6 endpoint"))?;
        let p = rest[end + 1..].strip_prefix(':').ok_or_else(|| wg_err(section, field, "Missing port"))?;
        (&rest[..end], p.trim())
    } else {
        let (h, p) = raw.rsplit_once(':').ok_or_else(|| wg_err(section, field, "Expected host:port"))?;
        (h.trim(), p.trim())
    };
    let port = port_str.parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(|| {
        wg_err(section, field, format!("Invalid port: '{}'", port_str))
    })?;
    if host.is_empty() {
        return Err(wg_err(section, field, "Empty endpoint host"));
    }
    Ok(WgEndpoint { host: host.to_string(), port })
}

pub fn parse_cidr(raw: &str, section: &str, field: &str) -> Result<IpNet> {
    let clean = raw.trim();
    if let Ok(net) = IpNet::from_str(clean) {
        return Ok(net);
    }
    if let Ok(ip) = IpAddr::from_str(clean) {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return Ok(IpNet::new(ip, prefix).unwrap());
    }
    Err(wg_err(section, field, format!("Invalid IP/CIDR: '{}'", clean)))
}

pub fn parse_reserved_bytes(raw: &str) -> Option<[u8; 3]> {
    let clean = raw.trim().trim_start_matches('[').trim_end_matches(']').trim();
    if clean.contains(',') {
        let n: Vec<u8> = clean.split(',').filter_map(|p| p.trim().parse().ok()).collect();
        if n.len() == 3 {
            return Some([n[0], n[1], n[2]]);
        }
    }
    let d = BASE64_STANDARD.decode(clean.as_bytes()).ok()?;
    (d.len() == 3).then(|| [d[0], d[1], d[2]])
}

pub fn parse_wireguard_ini(content: &str) -> Result<WgConfig> {
    let mut section = "";
    let mut private_key = None;
    let mut addresses = Vec::new();
    let mut dns = Vec::new();
    let mut reserved = [0u8; 3];
    let mut peers = Vec::new();
    let mut peer_pub: Option<String> = None;
    let mut peer_psk: Option<String> = None;
    let mut peer_ep: Option<WgEndpoint> = None;

    let flush_peer = |peers: &mut Vec<WgPeer>,
                      pubk: &mut Option<String>,
                      psk: &mut Option<String>,
                      ep: &mut Option<WgEndpoint>| {
        if let Some(pk) = pubk.take() {
            peers.push(WgPeer {
                public_key: pk,
                preshared_key: psk.take(),
                endpoint: ep.take(),
            });
        }
    };

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            if let Some((ck, cv)) = trimmed[1..].split_once('=') {
                if matches!(ck.trim().to_ascii_lowercase().as_str(), "clientid" | "client_id" | "reserved") {
                    if let Some(r) = parse_reserved_bytes(cv) {
                        reserved = r;
                    }
                }
            }
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            flush_peer(&mut peers, &mut peer_pub, &mut peer_psk, &mut peer_ep);
            let name = trimmed[1..trimmed.len() - 1].trim();
            section = if name.eq_ignore_ascii_case("interface") {
                "Interface"
            } else if name.eq_ignore_ascii_case("peer") {
                "Peer"
            } else {
                return Err(wg_err(&format!("Line {}", idx + 1), "Section", "Expected [Interface] or [Peer]"));
            };
            continue;
        }
        let (k_raw, v_raw) = trimmed
            .split_once('=')
            .ok_or_else(|| wg_err(section, &format!("Line {}", idx + 1), "Expected Key = Value"))?;
        let key = k_raw.trim().to_ascii_lowercase();
        let val = v_raw.split('#').next().unwrap_or("").trim();

        match (section, key.as_str()) {
            ("Interface", "privatekey") => {
                validate_base64_32_bytes(val, "Interface", "PrivateKey")?;
                private_key = Some(val.to_string());
            }
            ("Interface", "address") => {
                for item in val.split(',') {
                    addresses.push(parse_cidr(item, "Interface", "Address")?);
                }
            }
            ("Interface", "dns") => {
                for item in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    dns.push(IpAddr::from_str(item).map_err(|_| wg_err("Interface", "DNS", item))?);
                }
            }
            (_, "reserved" | "clientid" | "client_id") => {
                if let Some(r) = parse_reserved_bytes(val) {
                    reserved = r;
                }
            }
            ("Peer", "publickey") => {
                validate_base64_32_bytes(val, "Peer", "PublicKey")?;
                peer_pub = Some(val.to_string());
            }
            ("Peer", "presharedkey") => {
                validate_base64_32_bytes(val, "Peer", "PresharedKey")?;
                peer_psk = Some(val.to_string());
            }
            ("Peer", "endpoint") => {
                peer_ep = Some(parse_endpoint(val, "Peer", "Endpoint")?);
            }
            ("", _) => return Err(wg_err(&format!("Line {}", idx + 1), "Syntax", "Directive outside section")),
            _ => {}
        }
    }
    flush_peer(&mut peers, &mut peer_pub, &mut peer_psk, &mut peer_ep);

    let private_key = private_key.ok_or_else(|| wg_err("Interface", "PrivateKey", "Missing PrivateKey"))?;
    if addresses.is_empty() {
        return Err(wg_err("Interface", "Address", "Missing Address"));
    }
    if peers.is_empty() {
        return Err(wg_err("Peer", "Peer", "Missing [Peer] with PublicKey"));
    }

    Ok(WgConfig {
        interface: WgInterface {
            private_key,
            addresses,
            dns,
            reserved,
        },
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wireguard_and_reserved() {
        let ini = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32, 2606:4700:110::2/128
DNS = 1.1.1.1
# ClientId = [12, 34, 56]

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = [2606:4700:d0::a29f:c001]:2408
"#;
        let cfg = parse_wireguard_ini(ini).unwrap();
        assert_eq!(cfg.interface.addresses.len(), 2);
        assert_eq!(cfg.interface.reserved, [12, 34, 56]);
        assert_eq!(cfg.peers[0].endpoint.as_ref().unwrap().port, 2408);
    }
}
