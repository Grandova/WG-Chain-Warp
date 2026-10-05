use crate::error::{ChainError, Result};
use crate::wireguard::model::{WgConfig, WgEndpoint, WgInterface, WgPeer};
use base64::prelude::*;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

pub fn validate_base64_32_bytes(key: &str, section: &str, field: &str) -> Result<()> {
    let clean = key.trim();
    if clean.len() != 44 {
        return Err(ChainError::WgParseError {
            section: section.to_string(),
            field: field.to_string(),
            message: format!(
                "Key must be a 44-character Base64 encoded string, got length {}",
                clean.len()
            ),
        });
    }

    let bytes = BASE64_STANDARD
        .decode(clean.as_bytes())
        .map_err(|e| ChainError::WgParseError {
            section: section.to_string(),
            field: field.to_string(),
            message: format!("Invalid Base64 encoding: {}", e),
        })?;

    if bytes.len() != 32 {
        return Err(ChainError::WgParseError {
            section: section.to_string(),
            field: field.to_string(),
            message: format!(
                "Key must decode to exactly 32 bytes (256 bits), got {} bytes",
                bytes.len()
            ),
        });
    }

    Ok(())
}

pub fn parse_endpoint(raw: &str, section: &str, field: &str) -> Result<WgEndpoint> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ChainError::WgParseError {
            section: section.to_string(),
            field: field.to_string(),
            message: "Endpoint cannot be empty".to_string(),
        });
    }

    // Handles [2001:db8::1]:51820 or 1.2.3.4:51820 or example.com:51820
    if raw.starts_with('[') {
        if let Some(bracket_end) = raw.find(']') {
            let host = &raw[1..bracket_end];
            let rest = &raw[bracket_end + 1..];
            if let Some(colon) = rest.find(':') {
                let port_str = &rest[colon + 1..].trim();
                let port = port_str.parse::<u16>().map_err(|_| ChainError::WgParseError {
                    section: section.to_string(),
                    field: field.to_string(),
                    message: format!("Invalid port number in IPv6 endpoint: '{}'", port_str),
                })?;
                if port == 0 {
                    return Err(ChainError::WgParseError {
                        section: section.to_string(),
                        field: field.to_string(),
                        message: "Port number cannot be 0".to_string(),
                    });
                }
                return Ok(WgEndpoint {
                    host: host.to_string(),
                    port,
                });
            }
        }
        return Err(ChainError::WgParseError {
            section: section.to_string(),
            field: field.to_string(),
            message: format!("Malformed IPv6 endpoint format: '{}'", raw),
        });
    }

    // host:port (IPv4 or hostname)
    let parts: Vec<&str> = raw.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(ChainError::WgParseError {
            section: section.to_string(),
            field: field.to_string(),
            message: format!("Endpoint must be in 'host:port' format, got '{}'", raw),
        });
    }

    let port_str = parts[0].trim();
    let host = parts[1].trim();

    if host.is_empty() {
        return Err(ChainError::WgParseError {
            section: section.to_string(),
            field: field.to_string(),
            message: "Endpoint host cannot be empty".to_string(),
        });
    }

    let port = port_str.parse::<u16>().map_err(|_| ChainError::WgParseError {
        section: section.to_string(),
        field: field.to_string(),
        message: format!("Invalid port number: '{}'", port_str),
    })?;

    if port == 0 {
        return Err(ChainError::WgParseError {
            section: section.to_string(),
            field: field.to_string(),
            message: "Port number cannot be 0".to_string(),
        });
    }

    Ok(WgEndpoint {
        host: host.to_string(),
        port,
    })
}

pub fn parse_cidr(raw: &str, section: &str, field: &str) -> Result<IpNet> {
    let clean = raw.trim();
    if let Ok(net) = IpNet::from_str(clean) {
        return Ok(net);
    }

    // If single IP without mask, default to /32 for IPv4 or /128 for IPv6
    if let Ok(ip) = IpAddr::from_str(clean) {
        return match ip {
            IpAddr::V4(v4) => Ok(IpNet::new(IpAddr::V4(v4), 32).unwrap()),
            IpAddr::V6(v6) => Ok(IpNet::new(IpAddr::V6(v6), 128).unwrap()),
        };
    }

    Err(ChainError::WgParseError {
        section: section.to_string(),
        field: field.to_string(),
        message: format!("Invalid IP address or CIDR network: '{}'", clean),
    })
}

pub fn parse_wireguard_ini(content: &str) -> Result<WgConfig> {
    let mut current_section: Option<String> = None;

    // Interface fields
    let mut private_key: Option<String> = None;
    let mut addresses: Vec<IpNet> = Vec::new();
    let mut dns: Vec<IpAddr> = Vec::new();
    let mut listen_port: Option<u16> = None;
    let mut mtu: Option<u16> = None;
    let mut ignored_scripts: Vec<(String, String)> = Vec::new();

    // Peers
    let mut peers: Vec<WgPeer> = Vec::new();
    let mut current_peer_pubkey: Option<String> = None;
    let mut current_peer_preshared: Option<String> = None;
    let mut current_peer_endpoint: Option<WgEndpoint> = None;
    let mut current_peer_allowed_ips: Vec<IpNet> = Vec::new();
    let mut current_peer_keepalive: Option<u16> = None;

    let finish_current_peer = |peers: &mut Vec<WgPeer>,
                               pubkey: &mut Option<String>,
                               psk: &mut Option<String>,
                               ep: &mut Option<WgEndpoint>,
                               allowed: &mut Vec<IpNet>,
                               keepalive: &mut Option<u16>|
     -> Result<()> {
        if let Some(pk) = pubkey.take() {
            validate_base64_32_bytes(&pk, "Peer", "PublicKey")?;
            if let Some(psk_val) = psk.as_ref() {
                validate_base64_32_bytes(psk_val, "Peer", "PresharedKey")?;
            }
            if allowed.is_empty() {
                // Default to 0.0.0.0/0, ::/0 if not provided
                allowed.push(IpNet::from_str("0.0.0.0/0").unwrap());
                allowed.push(IpNet::from_str("::/0").unwrap());
            }
            peers.push(WgPeer {
                public_key: pk,
                preshared_key: psk.take(),
                endpoint: ep.take(),
                allowed_ips: std::mem::take(allowed),
                persistent_keepalive: keepalive.take(),
            });
        }
        Ok(())
    };

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        // Section header
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section_name = &trimmed[1..trimmed.len() - 1].trim();
            if section_name.eq_ignore_ascii_case("interface") {
                if current_section.as_deref() == Some("Peer") {
                    finish_current_peer(
                        &mut peers,
                        &mut current_peer_pubkey,
                        &mut current_peer_preshared,
                        &mut current_peer_endpoint,
                        &mut current_peer_allowed_ips,
                        &mut current_peer_keepalive,
                    )?;
                }
                current_section = Some("Interface".to_string());
            } else if section_name.eq_ignore_ascii_case("peer") {
                if current_section.as_deref() == Some("Peer") {
                    finish_current_peer(
                        &mut peers,
                        &mut current_peer_pubkey,
                        &mut current_peer_preshared,
                        &mut current_peer_endpoint,
                        &mut current_peer_allowed_ips,
                        &mut current_peer_keepalive,
                    )?;
                }
                current_section = Some("Peer".to_string());
            } else {
                return Err(ChainError::WgParseError {
                    section: format!("Line {}", line_num),
                    field: "SectionHeader".to_string(),
                    message: format!("Unknown section '[{}]', expected [Interface] or [Peer]", section_name),
                });
            }
            continue;
        }

        let section = match current_section.as_deref() {
            Some(s) => s,
            None => {
                return Err(ChainError::WgParseError {
                    section: format!("Line {}", line_num),
                    field: "Syntax".to_string(),
                    message: format!("Key-value pair '{}' found outside of any section", trimmed),
                });
            }
        };

        // Split key = value
        let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(ChainError::WgParseError {
                section: section.to_string(),
                field: format!("Line {}", line_num),
                message: format!("Expected 'Key = Value', got '{}'", trimmed),
            });
        }

        let key = parts[0].trim();
        // Remove trailing comment from value if present
        let mut value = parts[1].trim();
        if let Some(comment_pos) = value.find('#') {
            value = value[..comment_pos].trim();
        }

        match section {
            "Interface" => {
                if key.eq_ignore_ascii_case("privatekey") {
                    validate_base64_32_bytes(value, "Interface", "PrivateKey")?;
                    private_key = Some(value.to_string());
                } else if key.eq_ignore_ascii_case("address") {
                    for item in value.split(',') {
                        let cidr = parse_cidr(item.trim(), "Interface", "Address")?;
                        addresses.push(cidr);
                    }
                } else if key.eq_ignore_ascii_case("dns") {
                    for item in value.split(',') {
                        let item = item.trim();
                        if item.is_empty() {
                            continue;
                        }
                        let ip = IpAddr::from_str(item).map_err(|_| ChainError::WgParseError {
                            section: "Interface".to_string(),
                            field: "DNS".to_string(),
                            message: format!("Invalid DNS IP address: '{}'", item),
                        })?;
                        dns.push(ip);
                    }
                } else if key.eq_ignore_ascii_case("listenport") {
                    let port = value.parse::<u16>().map_err(|_| ChainError::WgParseError {
                        section: "Interface".to_string(),
                        field: "ListenPort".to_string(),
                        message: format!("Invalid ListenPort: '{}'", value),
                    })?;
                    listen_port = Some(port);
                } else if key.eq_ignore_ascii_case("mtu") {
                    let mtu_val = value.parse::<u16>().map_err(|_| ChainError::WgParseError {
                        section: "Interface".to_string(),
                        field: "MTU".to_string(),
                        message: format!("Invalid MTU: '{}'", value),
                    })?;
                    mtu = Some(mtu_val);
                } else if key.eq_ignore_ascii_case("postup")
                    || key.eq_ignore_ascii_case("postdown")
                    || key.eq_ignore_ascii_case("preup")
                    || key.eq_ignore_ascii_case("predown")
                {
                    // Never execute! Only record for reference
                    ignored_scripts.push((key.to_string(), value.to_string()));
                } else {
                    // Unknown or custom interface directive
                }
            }
            "Peer" => {
                if key.eq_ignore_ascii_case("publickey") {
                    validate_base64_32_bytes(value, "Peer", "PublicKey")?;
                    current_peer_pubkey = Some(value.to_string());
                } else if key.eq_ignore_ascii_case("presharedkey") {
                    validate_base64_32_bytes(value, "Peer", "PresharedKey")?;
                    current_peer_preshared = Some(value.to_string());
                } else if key.eq_ignore_ascii_case("endpoint") {
                    let ep = parse_endpoint(value, "Peer", "Endpoint")?;
                    current_peer_endpoint = Some(ep);
                } else if key.eq_ignore_ascii_case("allowedips") {
                    for item in value.split(',') {
                        let cidr = parse_cidr(item.trim(), "Peer", "AllowedIPs")?;
                        current_peer_allowed_ips.push(cidr);
                    }
                } else if key.eq_ignore_ascii_case("persistentkeepalive") {
                    let ka = value.parse::<u16>().map_err(|_| ChainError::WgParseError {
                        section: "Peer".to_string(),
                        field: "PersistentKeepalive".to_string(),
                        message: format!("Invalid PersistentKeepalive: '{}'", value),
                    })?;
                    current_peer_keepalive = Some(ka);
                }
            }
            _ => unreachable!(),
        }
    }

    if current_section.as_deref() == Some("Peer") {
        finish_current_peer(
            &mut peers,
            &mut current_peer_pubkey,
            &mut current_peer_preshared,
            &mut current_peer_endpoint,
            &mut current_peer_allowed_ips,
            &mut current_peer_keepalive,
        )?;
    }

    let priv_key = private_key.ok_or_else(|| ChainError::WgParseError {
        section: "Interface".to_string(),
        field: "PrivateKey".to_string(),
        message: "Missing required 'PrivateKey' in [Interface]".to_string(),
    })?;

    if addresses.is_empty() {
        return Err(ChainError::WgParseError {
            section: "Interface".to_string(),
            field: "Address".to_string(),
            message: "Missing required 'Address' in [Interface]".to_string(),
        });
    }

    if peers.is_empty() {
        return Err(ChainError::WgParseError {
            section: "Peer".to_string(),
            field: "Peer".to_string(),
            message: "At least one [Peer] section with PublicKey is required".to_string(),
        });
    }

    Ok(WgConfig {
        interface: WgInterface {
            private_key: priv_key,
            addresses,
            dns,
            listen_port,
            mtu,
            ignored_scripts,
        },
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_vpn1_and_warp_configs() {
        let vpn1_ini = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2/32
DNS = 10.2.0.1
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 198.51.100.1:51820
PersistentKeepalive = 25
"#;
        let parsed = parse_wireguard_ini(vpn1_ini).expect("Should parse valid config");
        assert_eq!(parsed.interface.addresses.len(), 1);
        assert_eq!(parsed.interface.dns.len(), 1);
        assert_eq!(parsed.interface.ignored_scripts.len(), 1);
        assert_eq!(parsed.interface.ignored_scripts[0].0, "PostUp");
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].endpoint.as_ref().unwrap().port, 51820);

        // Test redaction
        let redacted = parsed.redacted();
        assert_eq!(redacted.interface.private_key, "********");
    }

    #[test]
    fn test_ipv6_and_domain_endpoints() {
        let ep_v6 = parse_endpoint("[2606:4700:d0::a29f:c001]:2408", "Peer", "Endpoint").unwrap();
        assert_eq!(ep_v6.host, "2606:4700:d0::a29f:c001");
        assert_eq!(ep_v6.port, 2408);

        let ep_domain = parse_endpoint("engage.cloudflareclient.com:2408", "Peer", "Endpoint").unwrap();
        assert_eq!(ep_domain.host, "engage.cloudflareclient.com");
        assert_eq!(ep_domain.port, 2408);
    }

    #[test]
    fn test_invalid_key_length() {
        let invalid = r#"
[Interface]
PrivateKey = shortkey
Address = 10.2.0.2/32

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 1.1.1.1:51820
"#;
        let err = parse_wireguard_ini(invalid).unwrap_err();
        match err {
            ChainError::WgParseError { field, .. } => assert_eq!(field, "PrivateKey"),
            _ => panic!("Expected WgParseError"),
        }
    }

    #[test]
    fn test_invalid_endpoint_port() {
        let invalid = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2/32

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 1.1.1.1:99999
"#;
        let err = parse_wireguard_ini(invalid).unwrap_err();
        match err {
            ChainError::WgParseError { field, .. } => assert_eq!(field, "Endpoint"),
            _ => panic!("Expected WgParseError"),
        }
    }

    #[test]
    fn test_missing_private_key() {
        let invalid = r#"
[Interface]
Address = 10.2.0.2/32

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 1.1.1.1:51820
"#;
        let err = parse_wireguard_ini(invalid).unwrap_err();
        match err {
            ChainError::WgParseError { field, .. } => assert_eq!(field, "PrivateKey"),
            _ => panic!("Expected WgParseError"),
        }
    }

    #[test]
    fn test_missing_address() {
        let invalid = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 1.1.1.1:51820
"#;
        let err = parse_wireguard_ini(invalid).unwrap_err();
        match err {
            ChainError::WgParseError { field, .. } => assert_eq!(field, "Address"),
            _ => panic!("Expected WgParseError"),
        }
    }

    #[test]
    fn test_preshared_key_and_multiple_addresses() {
        let conf = r#"
# Sample test config
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2/32, 2606:4700:110:8f6f::2/128
DNS = 1.1.1.1, 1.0.0.1
PostUp = echo 'malicious bash command'
PostDown = echo 'down'

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
PresharedKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Endpoint = 162.159.192.1:2408
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"#;
        let parsed = parse_wireguard_ini(conf).expect("Must parse");
        assert_eq!(parsed.interface.addresses.len(), 2);
        assert_eq!(parsed.interface.dns.len(), 2);
        assert_eq!(parsed.interface.ignored_scripts.len(), 2);
        assert_eq!(parsed.interface.ignored_scripts[0].0, "PostUp");
        assert_eq!(parsed.peers[0].preshared_key.as_deref(), Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="));
        
        let redacted = parsed.redacted();
        assert_eq!(redacted.peers[0].preshared_key.as_deref(), Some("********"));
        assert_eq!(redacted.interface.private_key, "********");
    }
}
