use crate::error::{ChainError, Result};
use crate::model::config::{ChainProxyConfig, ParsedNodes, ProxyMode};
use crate::singbox::model::{DnsConfig, LogConfig, RouteConfig, SingBoxConfig};
use serde_json::json;

pub const DEFAULT_TUN_NAME: &str = "chain0";
pub const DEFAULT_TUN_IPV4: &str = "172.31.255.1/30";
pub const DEFAULT_TUN_IPV6: &str = "fdfe:dcba:9876::1/126";
pub const TEST_VPN1_PORT: u16 = 25431;
pub const TEST_WARP_PORT: u16 = 25432;
pub const DIRECT_ROUTING_MARK: u32 = 1024; // 0x400

pub fn generate_singbox_config(
    chain_config: &ChainProxyConfig,
    parsed: &ParsedNodes,
    uplink_interface: &str,
) -> Result<SingBoxConfig> {
    // 1. Log section
    let log = LogConfig {
        level: "info".to_string(),
        timestamp: true,
    };

    // Determine final outbound target based on active ProxyMode
    let final_target_outbound = match chain_config.mode {
        ProxyMode::WgChainWarp | ProxyMode::SocksChainWarp | ProxyMode::StandaloneWarp => "warp",
        ProxyMode::StandaloneWg => "vpn1",
        ProxyMode::StandaloneSocks => "socks-out",
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
                    "detour": final_target_outbound
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
            let mut target_dns = "1.1.1.1".to_string();
            if let Some(ref v2) = parsed.vpn2 {
                if !v2.interface.dns.is_empty() {
                    target_dns = v2.interface.dns[0].to_string();
                }
            } else if let Some(ref v1) = parsed.vpn1 {
                if !v1.interface.dns.is_empty() {
                    target_dns = v1.interface.dns[0].to_string();
                }
            }

            dns_servers.push(json!({
                "tag": "dns-chain",
                "type": "udp",
                "server": target_dns,
                "detour": final_target_outbound
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

    // 4. Outbounds & Endpoints
    let mut outbounds = Vec::new();
    let mut endpoints = Vec::new();

    // Base physical direct outbound
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
    outbounds.push(direct_obj);

    // Socks5 outbound (if used as relay or standalone egress)
    if let Some(ref s5) = parsed.socks5 {
        let tag = if chain_config.mode == ProxyMode::SocksChainWarp {
            "socks-relay"
        } else {
            "socks-out"
        };

        let mut socks_obj = json!({
            "type": "socks",
            "tag": tag,
            "server": s5.server,
            "server_port": s5.port,
            "version": "5",
            "detour": "physical-direct"
        });
        if let Some(ref u) = s5.username {
            socks_obj["username"] = json!(u);
        }
        if let Some(ref p) = s5.password {
            socks_obj["password"] = json!(p);
        }
        outbounds.push(socks_obj);
    }

    let allowed_ips = if chain_config.routing.ipv6 {
        vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
    } else {
        vec!["0.0.0.0/0".to_string()]
    };

    // WireGuard VPN1 Endpoint (if configured)
    if let Some(ref vpn1_wg) = parsed.vpn1 {
        let vpn1_peer = vpn1_wg.peers.first().ok_or_else(|| {
            ChainError::ValidationError("VPN1 missing peer".to_string())
        })?;
        let vpn1_endpoint = vpn1_peer.endpoint.as_ref().ok_or_else(|| {
            ChainError::ValidationError("VPN1 peer missing endpoint".to_string())
        })?;

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
            "allowed_ips": allowed_ips.clone()
        });
        if let Some(psk) = &vpn1_peer.preshared_key {
            vpn1_peer_obj["pre_shared_key"] = json!(psk);
        }

        endpoints.push(json!({
            "type": "wireguard",
            "tag": "vpn1",
            "address": vpn1_addresses,
            "private_key": vpn1_wg.interface.private_key,
            "peers": [vpn1_peer_obj],
            "detour": "physical-direct",
            "mtu": vpn1_wg.interface.mtu.unwrap_or(1420)
        }));
    }

    // Cloudflare WARP Endpoint (if configured)
    if let Some(ref vpn2_wg) = parsed.vpn2 {
        let vpn2_peer = vpn2_wg.peers.first().ok_or_else(|| {
            ChainError::ValidationError("WARP missing peer".to_string())
        })?;
        let vpn2_endpoint = vpn2_peer.endpoint.as_ref().ok_or_else(|| {
            ChainError::ValidationError("WARP peer missing endpoint".to_string())
        })?;

        let warp_addresses: Vec<String> = vpn2_wg
            .interface
            .addresses
            .iter()
            .filter(|a| chain_config.routing.ipv6 || a.addr().is_ipv4())
            .map(|a| a.to_string())
            .collect();

        let mut warp_peer_obj = json!({
            "address": vpn2_endpoint.host,
            "port": vpn2_endpoint.port,
            "public_key": vpn2_peer.public_key,
            "allowed_ips": allowed_ips
        });
        if let Some(psk) = &vpn2_peer.preshared_key {
            warp_peer_obj["pre_shared_key"] = json!(psk);
        }

        let warp_detour = match chain_config.mode {
            ProxyMode::WgChainWarp => "vpn1",
            ProxyMode::SocksChainWarp => "socks-relay",
            _ => "physical-direct",
        };

        endpoints.push(json!({
            "type": "wireguard",
            "tag": "warp",
            "address": warp_addresses,
            "private_key": vpn2_wg.interface.private_key,
            "peers": [warp_peer_obj],
            "detour": warp_detour,
            "mtu": vpn2_wg.interface.mtu.unwrap_or(1280)
        }));
    }

    // 5. Route Section
    let mut route_rules = Vec::new();

    // Rule: Sniff protocol
    route_rules.push(json!({ "action": "sniff" }));

    // Rule: DNS hijack
    route_rules.push(json!({
        "protocol": "dns",
        "action": "hijack-dns"
    }));

    // Route test inbounds according to active mode
    let test_vpn1_target = match chain_config.mode {
        ProxyMode::WgChainWarp | ProxyMode::StandaloneWg => "vpn1",
        ProxyMode::SocksChainWarp => "socks-relay",
        ProxyMode::StandaloneSocks => "socks-out",
        ProxyMode::StandaloneWarp => "warp",
    };
    route_rules.push(json!({
        "inbound": ["test-vpn1-in"],
        "outbound": test_vpn1_target
    }));

    let test_warp_target = match chain_config.mode {
        ProxyMode::StandaloneWg => "vpn1",
        ProxyMode::StandaloneSocks => "socks-out",
        _ => "warp",
    };
    route_rules.push(json!({
        "inbound": ["test-warp-in"],
        "outbound": test_warp_target
    }));

    // Underlay host routes to prevent TUN loops:
    // Route underlay endpoints (WireGuard remote endpoint, Socks5 server, or WARP endpoint) to physical-direct
    let mut underlay_hosts = Vec::new();
    if let Some(ref v1) = parsed.vpn1 {
        if let Some(host) = v1.peers.first().and_then(|p| p.endpoint.as_ref()).map(|e| &e.host) {
            underlay_hosts.push(host.clone());
        }
    }
    if let Some(ref s5) = parsed.socks5 {
        underlay_hosts.push(s5.server.clone());
    }
    if chain_config.mode == ProxyMode::StandaloneWarp {
        if let Some(ref v2) = parsed.vpn2 {
            if let Some(host) = v2.peers.first().and_then(|p| p.endpoint.as_ref()).map(|e| &e.host) {
                underlay_hosts.push(host.clone());
            }
        }
    }

    for host in underlay_hosts {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
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
                "domain": [host],
                "outbound": "physical-direct"
            }));
        }
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
        final_outbound: final_target_outbound.to_string(),
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
            mode: ProxyMode::WgChainWarp,
            uplink_interface: Some("eth0".to_string()),
            vpn1: VpnNodeConfig {
                name: "VPN1".to_string(),
                wireguard_config: vpn1_cfg.to_string(),
            },
            vpn2: VpnNodeConfig {
                name: "Cloudflare WARP".to_string(),
                wireguard_config: warp.to_string(),
            },
            socks5: None,
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0").unwrap();

        // Check modern endpoints array
        assert_eq!(singbox.endpoints.len(), 2);
        let vpn1_ep = singbox.endpoints.iter().find(|e| e["tag"] == "vpn1").unwrap();
        assert_eq!(vpn1_ep["detour"], "physical-direct");

        let warp_ep = singbox.endpoints.iter().find(|e| e["tag"] == "warp").unwrap();
        assert_eq!(warp_ep["detour"], "vpn1");

        // Check physical-direct outbound
        assert_eq!(singbox.outbounds.len(), 1);
        assert_eq!(singbox.outbounds[0]["tag"], "physical-direct");
        assert_eq!(singbox.outbounds[0]["bind_interface"], "eth0");

        // Check route final
        assert_eq!(singbox.route.final_outbound, "warp");
    }

    #[test]
    fn test_generator_socks_chain_warp() {
        use crate::proxy::socks5::Socks5Config;

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
            mode: ProxyMode::SocksChainWarp,
            uplink_interface: Some("eth0".to_string()),
            vpn1: VpnNodeConfig::default(),
            vpn2: VpnNodeConfig {
                name: "Cloudflare WARP".to_string(),
                wireguard_config: warp.to_string(),
            },
            socks5: Some(Socks5Config::parse("mockuser:mockpass@198.51.100.2:1080").unwrap()),
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0").unwrap();

        // Endpoint: warp with detour socks-relay
        assert_eq!(singbox.endpoints.len(), 1);
        assert_eq!(singbox.endpoints[0]["tag"], "warp");
        assert_eq!(singbox.endpoints[0]["detour"], "socks-relay");

        // Outbounds: physical-direct and socks-relay
        let socks_outbound = singbox.outbounds.iter().find(|o| o["tag"] == "socks-relay").unwrap();
        assert_eq!(socks_outbound["type"], "socks");
        assert_eq!(socks_outbound["server"], "198.51.100.2");
        assert_eq!(socks_outbound["server_port"], 1080);
        assert_eq!(socks_outbound["username"], "mockuser");
        assert_eq!(socks_outbound["password"], "mockpass");
        assert_eq!(socks_outbound["detour"], "physical-direct");

        assert_eq!(singbox.route.final_outbound, "warp");
    }

    #[test]
    fn test_generator_standalone_socks() {
        use crate::proxy::socks5::Socks5Config;

        let conf = ChainProxyConfig {
            enabled: true,
            mode: ProxyMode::StandaloneSocks,
            uplink_interface: Some("eth0".to_string()),
            vpn1: VpnNodeConfig::default(),
            vpn2: VpnNodeConfig::default(),
            socks5: Some(Socks5Config::parse("mockuser:mockpass@198.51.100.2:1080").unwrap()),
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0").unwrap();

        // No WireGuard endpoints in standalone socks
        assert_eq!(singbox.endpoints.len(), 0);

        // Outbound has socks-out
        let socks_outbound = singbox.outbounds.iter().find(|o| o["tag"] == "socks-out").unwrap();
        assert_eq!(socks_outbound["type"], "socks");
        assert_eq!(socks_outbound["detour"], "physical-direct");

        assert_eq!(singbox.route.final_outbound, "socks-out");
    }

    #[test]
    fn test_generator_standalone_wg() {
        let vpn1_cfg = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2/32

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
"#;

        let conf = ChainProxyConfig {
            enabled: true,
            mode: ProxyMode::StandaloneWg,
            uplink_interface: Some("eth0".to_string()),
            vpn1: VpnNodeConfig {
                name: "VPN1".to_string(),
                wireguard_config: vpn1_cfg.to_string(),
            },
            vpn2: VpnNodeConfig::default(),
            socks5: None,
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0").unwrap();

        // Only vpn1 endpoint
        assert_eq!(singbox.endpoints.len(), 1);
        assert_eq!(singbox.endpoints[0]["tag"], "vpn1");
        assert_eq!(singbox.endpoints[0]["detour"], "physical-direct");

        assert_eq!(singbox.route.final_outbound, "vpn1");
    }
}
