use crate::error::{ChainError, Result};
use crate::model::config::{ChainProxyConfig, ParsedNodes, ProxyMode};
use crate::singbox::model::{DnsConfig, LogConfig, RouteConfig, SingBoxConfig};
use serde_json::json;

pub const DEFAULT_TUN_NAME: &str = "chain0";
pub const DEFAULT_TUN_IPV4: &str = "172.31.255.1/30";
pub const DEFAULT_TUN_IPV6: &str = "fdfe:dcba:9876::1/126";
pub const TEST_VPN1_PORT: u16 = 25431;
pub const TEST_WARP_PORT: u16 = 25432;
pub const DIRECT_ROUTING_MARK: u32 = crate::network::iproute::MARK_PHYSICAL_DIRECT;

pub fn generate_singbox_config(
    chain_config: &ChainProxyConfig,
    parsed: &ParsedNodes,
    uplink_interface: &str,
    local_ip: Option<&str>,
) -> Result<SingBoxConfig> {
    let _ = local_ip;
    // 1. Log section
    let sb_level = match chain_config.log_level.to_lowercase().as_str() {
        "debug" => "debug".to_string(),
        "warn" => "warn".to_string(),
        "none" => "panic".to_string(),
        _ => "info".to_string(),
    };
    let log = LogConfig {
        level: sb_level,
        timestamp: true,
    };

    if chain_config.mode == ProxyMode::Socks5Server {
        let server = chain_config
            .socks5_server
            .as_ref()
            .ok_or_else(|| ChainError::ValidationError("尚未配置 SOCKS5 服务端".to_string()))?;
        server.validate()?;
        let mut outbound = json!({"type": "direct", "tag": "physical-direct"});
        if !uplink_interface.is_empty() {
            outbound["bind_interface"] = json!(uplink_interface);
        }
        return Ok(SingBoxConfig {
            log,
            dns: DnsConfig {
                servers: vec![json!({"type": "local", "tag": "dns-direct"})],
                final_server: Some("dns-direct".to_string()),
                rules: vec![],
                strategy: Some("prefer_ipv4".to_string()),
            },
            inbounds: vec![json!({
                "type": "socks", "tag": "socks-server", "listen": server.listen,
                "listen_port": server.port, "users": server.users
            })],
            endpoints: vec![],
            outbounds: vec![outbound],
            route: RouteConfig {
                auto_detect_interface: true,
                default_domain_resolver: Some("dns-direct".to_string()),
                final_outbound: "physical-direct".to_string(),
                rules: vec![],
            },
        });
    }

    // Determine final outbound target based on active ProxyMode
    let final_target_outbound = match chain_config.mode {
        ProxyMode::WgChainWarp | ProxyMode::SocksChainWarp | ProxyMode::StandaloneWarp => "warp",
        ProxyMode::StandaloneWg => "vpn1",
        ProxyMode::StandaloneSocks => "socks-out",
        ProxyMode::Socks5Server => "physical-direct",
    };

    // 2. DNS Section (Modern sing-box 1.14+ format)
    let mut dns_servers = Vec::new();
    let final_dns;
    let dns_transport = if chain_config.mode == ProxyMode::StandaloneSocks {
        "tcp"
    } else {
        "udp"
    };

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
                    "type": dns_transport,
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
            dns_servers.push(json!({
                "tag": "dns-chain",
                "type": dns_transport,
                "server": "1.1.1.1",
                "detour": final_target_outbound
            }));
            dns_servers.push(json!({
                "tag": "dns-chain-backup",
                "type": dns_transport,
                "server": "8.8.8.8",
                "detour": final_target_outbound
            }));
            if let Some(ref v1) = parsed.vpn1 {
                if !v1.interface.dns.is_empty() {
                    let vpn_dns = v1.interface.dns[0].to_string();
                    if vpn_dns != "1.1.1.1" && vpn_dns != "8.8.8.8" {
                        dns_servers.push(json!({
                            "tag": "dns-vpn-node",
                            "type": "udp",
                            "server": vpn_dns,
                            "detour": final_target_outbound
                        }));
                    }
                }
            }
            dns_servers.push(json!({
                "tag": "dns-direct",
                "type": "local",
                "detour": "physical-direct"
            }));
            final_dns = Some("dns-chain".to_string());
        }
    }

    if !dns_servers.iter().any(|s| s["tag"] == "dns-direct") {
        dns_servers
            .push(json!({"tag": "dns-direct", "type": "local", "detour": "physical-direct"}));
    }

    #[cfg(target_os = "linux")]
    {
        let tun_subnets =
            [DEFAULT_TUN_IPV4, DEFAULT_TUN_IPV6].map(|s| s.parse::<ipnet::IpNet>().unwrap());
        let local_ip_addr = local_ip.and_then(|s| s.parse::<std::net::IpAddr>().ok());
        let server = ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"]
            .iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .flat_map(|text| {
                text.lines()
                    .filter_map(|line| {
                        let mut fields = line.split_whitespace();
                        if fields.next() == Some("nameserver") {
                            fields
                                .next()
                                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .find(|ip| {
                !ip.is_loopback()
                    && !ip.is_unspecified()
                    && Some(*ip) != local_ip_addr
                    && !tun_subnets.iter().any(|subnet| subnet.contains(ip))
            });
        let server = server.unwrap_or_else(|| "1.1.1.1".parse().unwrap());
        for dns in &mut dns_servers {
            if dns["tag"] == "dns-direct" {
                *dns = json!({"tag": "dns-direct", "type": "udp", "server": server.to_string(), "detour": "physical-direct"});
            }
        }
    }

    let dns = DnsConfig {
        servers: dns_servers,
        final_server: final_dns,
        rules: Vec::new(),
        strategy: Some("prefer_ipv4".to_string()),
    };

    // 3. Inbounds (High-performance mixed TUN stack)
    let mut inbounds = Vec::new();
    let mut tun_addresses = vec![json!(DEFAULT_TUN_IPV4)];
    if chain_config.routing.ipv6 {
        tun_addresses.push(json!(DEFAULT_TUN_IPV6));
    }

    let mut route_exclude_addresses = vec![
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
    ];
    if chain_config.routing.ipv6 {
        route_exclude_addresses.push("fc00::/7".to_string());
    }

    let tun_inbound = json!({
        "type": "tun",
        "tag": "tun-in",
        "interface_name": DEFAULT_TUN_NAME,
        "address": tun_addresses,
        "auto_route": false,
        "strict_route": false,
        "route_exclude_address": route_exclude_addresses,
        "stack": "mixed",
        "endpoint_independent_nat": true,
        "iproute2_table_index": crate::network::iproute::HOST_TABLE,
        "iproute2_rule_index": 9000
    });
    inbounds.push(tun_inbound);

    // Local loopback test inbounds for non-disruptive per-hop verification
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

    if let Some(ref vpn1_wg) = parsed.vpn1 {
        let vpn1_peer = vpn1_wg
            .peers
            .first()
            .ok_or_else(|| ChainError::ValidationError("VPN1 missing peer".to_string()))?;
        let vpn1_endpoint = vpn1_peer
            .endpoint
            .as_ref()
            .ok_or_else(|| ChainError::ValidationError("VPN1 peer missing endpoint".to_string()))?;

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

    if let Some(ref vpn2_wg) = parsed.vpn2 {
        let vpn2_peer = vpn2_wg
            .peers
            .first()
            .ok_or_else(|| ChainError::ValidationError("WARP missing peer".to_string()))?;
        let vpn2_endpoint = vpn2_peer
            .endpoint
            .as_ref()
            .ok_or_else(|| ChainError::ValidationError("WARP peer missing endpoint".to_string()))?;

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

    route_rules.push(json!({
        "action": "sniff",
        "timeout": "100ms"
    }));

    route_rules.push(json!({
        "protocol": "dns",
        "action": "hijack-dns"
    }));
    route_rules.push(json!({
        "port": [53],
        "action": "hijack-dns"
    }));

    route_rules.push(json!({
        "ip_is_private": true,
        "outbound": "physical-direct"
    }));

    if !chain_config.routing.ipv6 {
        route_rules.push(json!({
            "ip_version": 6,
            "action": "reject"
        }));
    }

    if chain_config.mode == ProxyMode::StandaloneSocks {
        route_rules.push(json!({
            "inbound": ["test-warp-in"], "action": "resolve",
            "server": dns.final_server, "strategy": "ipv4_only"
        }));
    }

    let test_vpn1_target = match chain_config.mode {
        ProxyMode::WgChainWarp | ProxyMode::StandaloneWg => "vpn1",
        ProxyMode::SocksChainWarp => "socks-relay",
        ProxyMode::StandaloneSocks => "socks-out",
        ProxyMode::Socks5Server => "physical-direct",
        ProxyMode::StandaloneWarp => "warp",
    };
    route_rules.push(json!({
        "inbound": ["test-vpn1-in"],
        "outbound": test_vpn1_target
    }));

    let test_warp_target = match chain_config.mode {
        ProxyMode::StandaloneWg => "vpn1",
        ProxyMode::StandaloneSocks => "socks-out",
        ProxyMode::Socks5Server => "physical-direct",
        _ => "warp",
    };
    route_rules.push(json!({
        "inbound": ["test-warp-in"],
        "outbound": test_warp_target
    }));

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
    fn socks_server_is_authenticated_direct_only_without_tun() {
        let config: ChainProxyConfig = serde_json::from_value(json!({
            "mode": "socks5_server",
            "socks5_server": {"listen": "::", "port": 1080,
                "users": [{"username": "alice", "password": "secret"}]}
        }))
        .unwrap();
        let generated =
            generate_singbox_config(&config, &config.parse_and_validate().unwrap(), "eth0", None)
                .unwrap();
        assert_eq!(generated.inbounds.len(), 1);
        assert_eq!(generated.inbounds[0]["type"], "socks");
        assert_eq!(generated.inbounds[0]["listen"], "::");
        assert_eq!(generated.inbounds[0]["users"][0]["password"], "secret");
        assert_eq!(generated.outbounds.len(), 1);
        assert_eq!(generated.outbounds[0]["type"], "direct");
        assert!(generated.outbounds[0].get("routing_mark").is_none());
        assert!(generated.endpoints.is_empty());
        assert_eq!(
            config.redacted().socks5_server.unwrap().users[0].password,
            "********"
        );
    }

    #[test]
    fn standalone_socks_resolves_dns_over_tcp_through_proxy() {
        for mode in ["chain", "custom"] {
            let config: ChainProxyConfig = serde_json::from_value(json!({
                "mode": "standalone_socks", "socks5": {"server": "192.0.2.1", "port": 1080},
                "dns": {"mode": mode, "custom_servers": ["1.1.1.1"]}
            }))
            .unwrap();
            let generated = generate_singbox_config(
                &config,
                &config.parse_and_validate().unwrap(),
                "eth0",
                None,
            )
            .unwrap();
            for server in &generated.dns.servers {
                if server["detour"] == "socks-out" {
                    assert_eq!(server["type"], "tcp");
                }
            }
            assert!(generated
                .route
                .rules
                .iter()
                .any(|r| r["action"] == "resolve"
                    && r["server"] == generated.dns.final_server.as_deref().unwrap()));
        }
    }

    #[test]
    fn host_routing_never_enables_singbox_auto_route() {
        let mut config = ChainProxyConfig {
            mode: ProxyMode::StandaloneSocks,
            socks5: Some(crate::proxy::socks5::Socks5Config::parse("192.0.2.1:1080").unwrap()),
            ..ChainProxyConfig::default()
        };
        for host in [false, true] {
            for mode in ["chain", "physical", "custom"] {
                config.routing.proxy_host_outbound = host;
                config.dns.mode = mode.to_string();
                config.dns.custom_servers = vec!["1.1.1.1".to_string()];
                let generated = generate_singbox_config(
                    &config,
                    &config.parse_and_validate().unwrap(),
                    "eth0",
                    None,
                )
                .unwrap();
                assert_eq!(generated.inbounds[0]["auto_route"], false);
                assert_eq!(generated.inbounds[0]["stack"], "mixed");
                assert!(generated
                    .dns
                    .servers
                    .iter()
                    .any(|s| s["tag"] == "dns-direct"));
            }
        }
    }

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
            socks5_server: None,
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
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        assert_eq!(singbox.endpoints.len(), 2);
        let vpn1_ep = singbox
            .endpoints
            .iter()
            .find(|e| e["tag"] == "vpn1")
            .unwrap();
        assert_eq!(vpn1_ep["detour"], "physical-direct");

        let warp_ep = singbox
            .endpoints
            .iter()
            .find(|e| e["tag"] == "warp")
            .unwrap();
        assert_eq!(warp_ep["detour"], "vpn1");

        assert_eq!(singbox.outbounds.len(), 1);
        assert_eq!(singbox.outbounds[0]["tag"], "physical-direct");
        assert_eq!(singbox.outbounds[0]["bind_interface"], "eth0");
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
            socks5_server: None,
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
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        assert_eq!(singbox.endpoints.len(), 1);
        assert_eq!(singbox.endpoints[0]["tag"], "warp");
        assert_eq!(singbox.endpoints[0]["detour"], "socks-relay");

        let socks_outbound = singbox
            .outbounds
            .iter()
            .find(|o| o["tag"] == "socks-relay")
            .unwrap();
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
            socks5_server: None,
            mode: ProxyMode::StandaloneSocks,
            uplink_interface: Some("eth0".to_string()),
            vpn1: VpnNodeConfig::default(),
            vpn2: VpnNodeConfig::default(),
            socks5: Some(Socks5Config::parse("mockuser:mockpass@198.51.100.2:1080").unwrap()),
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        assert_eq!(singbox.endpoints.len(), 0);

        let socks_outbound = singbox
            .outbounds
            .iter()
            .find(|o| o["tag"] == "socks-out")
            .unwrap();
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
            socks5_server: None,
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
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        assert_eq!(singbox.endpoints.len(), 1);
        assert_eq!(singbox.endpoints[0]["tag"], "vpn1");
        assert_eq!(singbox.endpoints[0]["detour"], "physical-direct");
        assert_eq!(singbox.route.final_outbound, "vpn1");
    }

    #[test]
    fn test_generator_ipv4_only_rejects_aaaa() {
        let conf = ChainProxyConfig {
            enabled: true,
            socks5_server: None,
            mode: ProxyMode::StandaloneWg,
            uplink_interface: Some("eth0".to_string()),
            vpn1: VpnNodeConfig {
                name: "VPN1".to_string(),
                wireguard_config: "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n".to_string(),
            },
            vpn2: VpnNodeConfig::default(),
            socks5: None,
            routing: RoutingConfig {
                ipv6: false,
                ..RoutingConfig::default()
            },
            dns: DnsConfig::default(),
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        let ipv6_route_rule = singbox
            .route
            .rules
            .iter()
            .find(|r| r.get("ip_version").and_then(|v| v.as_i64()) == Some(6))
            .expect("Should have IPv6 route reject rule");
        assert_eq!(ipv6_route_rule["action"], "reject");
    }

    #[test]
    fn test_generator_route_exclude_and_private_bypass() {
        let conf = ChainProxyConfig {
            enabled: true,
            socks5_server: None,
            mode: ProxyMode::StandaloneWg,
            uplink_interface: Some("eth0".to_string()),
            vpn1: VpnNodeConfig {
                name: "VPN1".to_string(),
                wireguard_config: "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n".to_string(),
            },
            vpn2: VpnNodeConfig::default(),
            socks5: None,
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox =
            generate_singbox_config(&conf, &parsed, "eth0", Some("10.82.160.94")).unwrap();

        let tun_in = singbox
            .inbounds
            .iter()
            .find(|i| i["tag"] == "tun-in")
            .unwrap();
        let excludes = tun_in["route_exclude_address"]
            .as_array()
            .expect("route_exclude_address must be an array");
        assert!(excludes.iter().any(|v| v == "10.0.0.0/8"));
        assert!(excludes.iter().any(|v| v == "172.16.0.0/12"));
        assert!(excludes.iter().any(|v| v == "192.168.0.0/16"));
        assert!(
            tun_in.get("sniff").is_none(),
            "Legacy inbound sniff field must not be present"
        );

        let private_rule = singbox
            .route
            .rules
            .iter()
            .find(|r| r.get("ip_is_private").and_then(|v| v.as_bool()) == Some(true))
            .expect("Must have ip_is_private bypass rule");
        assert_eq!(private_rule["outbound"], "physical-direct");

        let sniff_rule = singbox
            .route
            .rules
            .iter()
            .find(|r| r.get("action").and_then(|v| v.as_str()) == Some("sniff"))
            .expect("Must have sniff action rule");
        assert_eq!(sniff_rule["timeout"], "100ms");
    }
}
