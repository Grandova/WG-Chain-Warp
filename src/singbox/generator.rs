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
    // DNS over TCP works through SOCKS CONNECT even when UDP ASSOCIATE is unavailable.
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
            // Default: chain (prevent DNS leaks through tunnel)
            // Use 1.1.1.1 (Cloudflare) and 8.8.8.8 (Google) routed through final_target_outbound
            // This guarantees genuine IP resolution and avoids commercial VPN threat-protection sinkholes (such as NordVPN 192.0.0.88).
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
        // resolved includes chain0 DNS while it is running; reload must not use
        // that DNS (or our LAN listener) to bootstrap the tunnel itself.
        let tun_subnets =
            [DEFAULT_TUN_IPV4, DEFAULT_TUN_IPV6].map(|s| s.parse::<ipnet::IpNet>().unwrap());
        let local_ip = local_ip.and_then(|s| s.parse::<std::net::IpAddr>().ok());
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
                    && Some(*ip) != local_ip
                    && !tun_subnets.iter().any(|subnet| subnet.contains(ip))
            });
        let server = server.ok_or_else(|| ChainError::ValidationError(
            "Physical DNS requires an upstream nameserver outside loopback, chain0 and the local gateway address in /etc/resolv.conf or /run/systemd/resolve/resolv.conf".to_string()
        ))?;
        for dns in &mut dns_servers {
            if dns["tag"] == "dns-direct" {
                *dns = json!({"tag": "dns-direct", "type": "udp", "server": server.to_string(), "detour": "physical-direct"});
            }
        }
    }

    let dns_rules = Vec::new();

    let dns = DnsConfig {
        servers: dns_servers,
        final_server: final_dns,
        rules: dns_rules,
        strategy: Some("prefer_ipv4".to_string()),
    };

    // 3. Inbounds
    let mut inbounds = Vec::new();

    // Modern TUN Inbound with gVisor userspace stack for gateway forwarding
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
    for subnet in chain_config.get_effective_forwarded_subnets(None) {
        if !route_exclude_addresses.contains(&subnet) {
            route_exclude_addresses.push(subnet);
        }
    }

    let tun_inbound = json!({
        "type": "tun",
        "tag": "tun-in",
        "interface_name": DEFAULT_TUN_NAME,
        "address": tun_addresses,
        "auto_route": false,
        "strict_route": false,
        "route_exclude_address": route_exclude_addresses,
        "stack": "gvisor",
        "endpoint_independent_nat": true,
        "iproute2_table_index": crate::network::iproute::HOST_TABLE,
        "iproute2_rule_index": 9000
    });
    inbounds.push(tun_inbound);

    // Direct DNS listener inbound for transparent gateway / LAN DNS queries
    if chain_config.is_forwarding_enabled() {
        let listen_ip = local_ip.unwrap_or("0.0.0.0");
        inbounds.push(json!({
            "type": "direct",
            "tag": "dns-in",
            "network": "udp",
            "listen": listen_ip,
            "listen_port": 53
        }));
        inbounds.push(json!({
            "type": "direct",
            "tag": "dns-in-tcp",
            "network": "tcp",
            "listen": listen_ip,
            "listen_port": 53
        }));
    }

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

    // Cloudflare WARP Endpoint (if configured)
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

    // Protocol Sniff with explicit timeout to prevent connection stall
    route_rules.push(json!({
        "action": "sniff",
        "timeout": "300ms"
    }));

    // Rule: Direct DNS inbound hijack
    if chain_config.is_forwarding_enabled() {
        route_rules.push(json!({
            "inbound": ["dns-in", "dns-in-tcp"],
            "action": "hijack-dns"
        }));
    }

    // Rule: DNS hijack (support both protocol dns and port 53)
    route_rules.push(json!({
        "protocol": "dns",
        "action": "hijack-dns"
    }));
    route_rules.push(json!({
        "port": [53],
        "action": "hijack-dns"
    }));

    // Bypass private LAN traffic directly to physical-direct (prevents routing loops)
    route_rules.push(json!({
        "ip_is_private": true,
        "outbound": "physical-direct"
    }));

    // Strictly reject any IPv6 traffic when running in IPv4-only mode
    if !chain_config.routing.ipv6 {
        route_rules.push(json!({
            "ip_version": 6,
            "action": "reject"
        }));
    }

    if chain_config.mode == ProxyMode::StandaloneSocks {
        // Resolve here so upstream SOCKS DNS cannot hide a broken chain resolver.
        route_rules.push(json!({
            "inbound": ["test-warp-in"], "action": "resolve",
            "server": dns.final_server, "strategy": "ipv4_only"
        }));
    }

    // Route test inbounds according to active mode
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
        assert!(!config.is_forwarding_enabled());
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
                assert!(generated
                    .dns
                    .servers
                    .iter()
                    .any(|s| s["tag"] == "dns-direct"));
                let private = generated
                    .route
                    .rules
                    .iter()
                    .position(|r| r["ip_is_private"] == true)
                    .unwrap();
                let dns = generated
                    .route
                    .rules
                    .iter()
                    .position(|r| r["action"] == "hijack-dns")
                    .unwrap();
                assert!(dns < private);
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
            gateway: crate::model::config::GatewayConfig::default(),
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        // Check modern endpoints array
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
            gateway: crate::model::config::GatewayConfig::default(),
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        // Endpoint: warp with detour socks-relay
        assert_eq!(singbox.endpoints.len(), 1);
        assert_eq!(singbox.endpoints[0]["tag"], "warp");
        assert_eq!(singbox.endpoints[0]["detour"], "socks-relay");

        // Outbounds: physical-direct and socks-relay
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
            gateway: crate::model::config::GatewayConfig::default(),
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        // No WireGuard endpoints in standalone socks
        assert_eq!(singbox.endpoints.len(), 0);

        // Outbound has socks-out
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
            gateway: crate::model::config::GatewayConfig::default(),
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        // Only vpn1 endpoint
        assert_eq!(singbox.endpoints.len(), 1);
        assert_eq!(singbox.endpoints[0]["tag"], "vpn1");
        assert_eq!(singbox.endpoints[0]["detour"], "physical-direct");

        assert_eq!(singbox.route.final_outbound, "vpn1");
    }

    #[test]
    fn test_generator_gateway_mode_dns() {
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
            gateway: crate::model::config::GatewayConfig {
                enabled: true,
                auto_allow_lan: true,
                allowed_subnets: vec!["10.82.160.0/24".to_string()],
            },
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox =
            generate_singbox_config(&conf, &parsed, "eth0", Some("10.82.160.94")).unwrap();

        // Check direct dns-in inbound
        let dns_in = singbox
            .inbounds
            .iter()
            .find(|i| i["tag"] == "dns-in")
            .unwrap();
        assert_eq!(dns_in["type"], "direct");
        assert_eq!(dns_in["listen"], "10.82.160.94");
        assert_eq!(dns_in["listen_port"], 53);

        // Check hijack-dns rule for dns-in
        let hijack_rule = singbox
            .route
            .rules
            .iter()
            .find(|r| {
                r.get("inbound")
                    .and_then(|ib| ib.as_array())
                    .map(|arr| arr.iter().any(|v| v == "dns-in"))
                    .unwrap_or(false)
            })
            .unwrap();
        assert_eq!(hijack_rule["action"], "hijack-dns");
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
            gateway: crate::model::config::GatewayConfig::default(),
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox = generate_singbox_config(&conf, &parsed, "eth0", None).unwrap();

        // Verify Route rules reject IPv6 traffic
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
            gateway: crate::model::config::GatewayConfig {
                enabled: true,
                auto_allow_lan: true,
                allowed_subnets: vec!["10.82.160.0/24".to_string()],
            },
            log_level: "info".to_string(),
        };

        let parsed = conf.parse_and_validate().unwrap();
        let singbox =
            generate_singbox_config(&conf, &parsed, "eth0", Some("10.82.160.94")).unwrap();

        // 1. Verify TUN inbound contains route_exclude_address for private subnets
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
        assert!(excludes.iter().any(|v| v == "10.82.160.0/24"));
        assert!(
            tun_in.get("sniff").is_none(),
            "Legacy inbound sniff field must not be present"
        );

        // 2. Verify route rule bypasses private destinations directly to physical-direct
        let private_rule = singbox
            .route
            .rules
            .iter()
            .find(|r| r.get("ip_is_private").and_then(|v| v.as_bool()) == Some(true))
            .expect("Must have ip_is_private bypass rule");
        assert_eq!(private_rule["outbound"], "physical-direct");

        // 3. Verify sniff action has 300ms timeout
        let sniff_rule = singbox
            .route
            .rules
            .iter()
            .find(|r| r.get("action").and_then(|v| v.as_str()) == Some("sniff"))
            .expect("Must have sniff action rule");
        assert_eq!(sniff_rule["timeout"], "300ms");
    }
}
