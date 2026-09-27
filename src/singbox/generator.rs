use crate::error::{ChainError, Result};
use crate::model::config::ChainProxyConfig;
use crate::singbox::model::{DnsConfig, LogConfig, RouteConfig, SingBoxConfig};
use crate::wireguard::model::WgConfig;
use serde_json::json;

pub const DEFAULT_TUN_NAME: &str = "chain0";
pub const DEFAULT_TUN_IPV4: &str = "172.31.255.1/30";
pub const DEFAULT_TUN_IPV6: &str = "fdfe:dcba:9876::1/126";
pub const TEST_VPN1_PORT: u16 = 25431;
pub const TEST_WARP_PORT: u16 = 25432;
pub const DIRECT_ROUTING_MARK: u32 = 1024; // 0x400

pub fn generate_singbox_config(
    chain_config: &ChainProxyConfig,
    vpn1_wg: &WgConfig,
    vpn2_wg: &WgConfig,
    uplink_interface: &str,
) -> Result<SingBoxConfig> {
    let vpn1_peer = vpn1_wg
        .peers
        .first()
        .ok_or_else(|| ChainError::ValidationError("VPN1 missing peer".to_string()))?;
    let vpn1_endpoint = vpn1_peer
        .endpoint
        .as_ref()
        .ok_or_else(|| ChainError::ValidationError("VPN1 peer missing endpoint".to_string()))?;

    let vpn2_peer = vpn2_wg
        .peers
        .first()
        .ok_or_else(|| ChainError::ValidationError("VPN2 missing peer".to_string()))?;
    let vpn2_endpoint = vpn2_peer
        .endpoint
        .as_ref()
        .ok_or_else(|| ChainError::ValidationError("VPN2 peer missing endpoint".to_string()))?;

    // 1. Log section
    let log = LogConfig {
        level: "info".to_string(),
        timestamp: true,
    };

    // 2. DNS Section (Modern sing-box 1.14+ format)
    let mut dns_servers = Vec::new();
    let final_dns;

    match chain_config.dns.mode.as_str() {
        "physical" => {
            dns_servers.push(json!({
                "tag": "dns-direct",
                "type": "local",
                "detour": "physical-direct"
            }));
            final_dns = Some("dns-direct".to_string());
        }
        "custom" => {
            for (idx, s) in chain_config.dns.custom_servers.iter().enumerate() {
                let tag = format!("dns-custom-{}", idx);
                dns_servers.push(json!({
                    "tag": tag,
                    "type": "udp",
                    "server": s,
                    "detour": "warp"
                }));
            }
            if !dns_servers.is_empty() {
                final_dns = Some("dns-custom-0".to_string());
            } else {
                dns_servers.push(json!({
                    "tag": "dns-direct",
                    "type": "local",
                    "detour": "physical-direct"
                }));
                final_dns = Some("dns-direct".to_string());
            }
        }
        _ => {
            // Default: chain (prevent DNS leaks through tunnel)
            let target_dns_server = if !vpn2_wg.interface.dns.is_empty() {
                vpn2_wg.interface.dns[0].to_string()
            } else if !vpn1_wg.interface.dns.is_empty() {
                vpn1_wg.interface.dns[0].to_string()
            } else {
                "1.1.1.1".to_string()
            };

            dns_servers.push(json!({
                "tag": "dns-chain",
                "type": "udp",
                "server": target_dns_server,
                "detour": "warp"
            }));
            dns_servers.push(json!({
                "tag": "dns-direct",
                "type": "local",
                "detour": "physical-direct"
            }));
            final_dns = Some("dns-chain".to_string());
        }
    }

    let dns = DnsConfig {
        servers: dns_servers,
        final_server: final_dns,
        rules: vec![],
        strategy: if chain_config.routing.ipv6 {
            Some("prefer_ipv4".to_string())
        } else {
            Some("ipv4_only".to_string())
        },
    };

    // 3. Inbounds
    let mut inbounds = Vec::new();

    // Modern TUN Inbound for sing-box 1.14+
    let mut tun_addresses = vec![json!(DEFAULT_TUN_IPV4)];
    if chain_config.routing.ipv6 {
        tun_addresses.push(json!(DEFAULT_TUN_IPV6));
    }

    inbounds.push(json!({
        "type": "tun",
        "tag": "tun-in",
        "interface_name": DEFAULT_TUN_NAME,
        "address": tun_addresses,
        "auto_route": chain_config.routing.proxy_host_outbound,
        "strict_route": false,
        "stack": "mixed"
    }));

    // Test inbounds strictly bound to 127.0.0.1 for non-disruptive per-hop verification
    inbounds.push(json!({
        "type": "mixed",
        "tag": "test-vpn1-in",
        "listen": "127.0.0.1",
        "listen_port": TEST_VPN1_PORT
    }));

    inbounds.push(json!({
        "type": "mixed",
        "tag": "test-warp-in",
        "listen": "127.0.0.1",
        "listen_port": TEST_WARP_PORT
    }));

    // 4. Endpoints (Modern sing-box 1.14+ WireGuard Endpoints)
    let mut endpoints = Vec::new();

    // WARP Endpoint (detour to vpn1)
    let warp_addresses: Vec<String> = vpn2_wg
        .interface
        .addresses
        .iter()
        .filter(|a| chain_config.routing.ipv6 || a.addr().is_ipv4())
        .map(|a| a.to_string())
        .collect();

    let allowed_ips = if chain_config.routing.ipv6 {
        vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
    } else {
        vec!["0.0.0.0/0".to_string()]
    };

    let mut warp_peer_obj = json!({
        "address": vpn2_endpoint.host,
        "port": vpn2_endpoint.port,
        "public_key": vpn2_peer.public_key,
        "allowed_ips": allowed_ips
    });
    if let Some(psk) = &vpn2_peer.preshared_key {
        warp_peer_obj["pre_shared_key"] = json!(psk);
    }

    endpoints.push(json!({
        "type": "wireguard",
        "tag": "warp",
        "address": warp_addresses,
        "private_key": vpn2_wg.interface.private_key,
        "peers": [warp_peer_obj],
        "detour": "vpn1",
        "mtu": vpn2_wg.interface.mtu.unwrap_or(1280)
    }));

    // VPN1 Endpoint (detour to physical-direct)
    let vpn1_addresses: Vec<String> = vpn1_wg
        .interface
        .addresses
        .iter()
        .filter(|a| chain_config.routing.ipv6 || a.addr().is_ipv4())
        .map(|a| a.to_string())
        .collect();

    let mut vpn1_peer_obj = json!({
        "address": vpn1_endpoint.host,
        "port": vpn1_endpoint.port,
        "public_key": vpn1_peer.public_key,
        "allowed_ips": allowed_ips
    });
    if let Some(psk) = &vpn1_peer.preshared_key {
        vpn1_peer_obj["pre_shared_key"] = json!(psk);
    }

    let has_direct_binding = !uplink_interface.is_empty() || cfg!(target_os = "linux");

    let mut vpn1_endpoint_obj = json!({
        "type": "wireguard",
        "tag": "vpn1",
        "address": vpn1_addresses,
        "private_key": vpn1_wg.interface.private_key,
        "peers": [vpn1_peer_obj],
        "mtu": vpn1_wg.interface.mtu.unwrap_or(1420)
    });
    if has_direct_binding {
        vpn1_endpoint_obj["detour"] = json!("physical-direct");
    }
    endpoints.push(vpn1_endpoint_obj);

    // 5. Outbounds
    let mut direct_obj = json!({
        "type": "direct",
        "tag": "physical-direct"
    });
    if !uplink_interface.is_empty() {
        direct_obj["bind_interface"] = json!(uplink_interface);
    }
    if cfg!(target_os = "linux") {
        direct_obj["routing_mark"] = json!(DIRECT_ROUTING_MARK);
    }

    let mut outbounds = Vec::new();
    outbounds.push(direct_obj);

    // 6. Route Section
    let mut route_rules = Vec::new();

    // Rule: Sniff protocol
    route_rules.push(json!({
        "action": "sniff"
    }));

    // Rule: DNS hijack
    route_rules.push(json!({
        "protocol": "dns",
        "action": "hijack-dns"
    }));

    // Rule: Route test inbounds to their respective endpoints
    route_rules.push(json!({
        "inbound": ["test-vpn1-in"],
        "outbound": "vpn1"
    }));
    route_rules.push(json!({
        "inbound": ["test-warp-in"],
        "outbound": "warp"
    }));

    // Rule: Ensure VPN1 endpoint host/IP is NEVER intercepted by TUN
    if let Ok(ip) = vpn1_endpoint.host.parse::<std::net::IpAddr>() {
        let cidr = if ip.is_ipv4() {
            format!("{}/32", ip)
        } else {
            format!("{}/128", ip)
        };
        route_rules.push(json!({
            "ip_cidr": [cidr],
            "outbound": "physical-direct"
        }));
    } else {
        route_rules.push(json!({
            "domain": [vpn1_endpoint.host.clone()],
            "outbound": "physical-direct"
        }));
    }

    // Excluded destinations if specified
    if !chain_config.routing.exclude_destinations.is_empty() {
        route_rules.push(json!({
            "ip_cidr": chain_config.routing.exclude_destinations,
            "outbound": "physical-direct"
        }));
    }

    let route = RouteConfig {
        auto_detect_interface: true,
        default_domain_resolver: Some("dns-direct".to_string()),
        final_outbound: "warp".to_string(),
        rules: route_rules,
    };

    Ok(SingBoxConfig {
        log,
        dns,
        inbounds,
        endpoints,
        outbounds,
        route,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::config::{ChainProxyConfig, DnsConfig, RoutingConfig, VpnNodeConfig};

    #[test]
    fn test_generator_chain_structure() {
        let vpn1_cfg = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
"#;
        let warp = r#"
[Interface]
PrivateKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Address = 172.16.0.2/32

[Peer]
PublicKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
Endpoint = 162.159.192.1:2408
AllowedIPs = 0.0.0.0/0
"#;

        let conf = ChainProxyConfig {
            enabled: true,
            uplink_interface: Some("eth0".to_string()),
            vpn1: VpnNodeConfig {
                name: "VPN1".to_string(),
                wireguard_config: vpn1_cfg.to_string(),
            },
            vpn2: VpnNodeConfig {
                name: "Cloudflare WARP".to_string(),
                wireguard_config: warp.to_string(),
            },
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
        };

        let (p1, p2) = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &p1, &p2, "eth0").unwrap();

        // Check modern endpoints array
        assert_eq!(singbox.endpoints.len(), 2);
        assert_eq!(singbox.endpoints[0]["tag"], "warp");
        assert_eq!(singbox.endpoints[0]["detour"], "vpn1");

        assert_eq!(singbox.endpoints[1]["tag"], "vpn1");
        assert_eq!(singbox.endpoints[1]["detour"], "physical-direct");

        // Check physical-direct outbound
        assert_eq!(singbox.outbounds.len(), 1);
        assert_eq!(singbox.outbounds[0]["tag"], "physical-direct");
        assert_eq!(singbox.outbounds[0]["bind_interface"], "eth0");

        // Check route final
        assert_eq!(singbox.route.final_outbound, "warp");
    }
}
