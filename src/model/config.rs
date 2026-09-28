use crate::proxy::socks5::Socks5Config;
use crate::wireguard::model::WgConfig;
use crate::wireguard::parser::parse_wireguard_ini;
use crate::error::{ChainError, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// 1. Layer 1 WireGuard -> Layer 2 Cloudflare WARP (双层链式: WG -> WARP)
    WgChainWarp,

    /// 2. Layer 1 Socks5 -> Layer 2 Cloudflare WARP (双层链式: Socks5 作为入口中继 WARP)
    SocksChainWarp,

    /// 3. Standalone WireGuard -> Internet (单独 WireGuard 直连出站，不带 WARP)
    StandaloneWg,

    /// 4. Standalone Socks5 -> Internet (单独 Socks5 代理直连出站，不带 WARP)
    StandaloneSocks,

    /// 5. Standalone Cloudflare WARP -> Internet (单独 WARP 直连出站)
    StandaloneWarp,
}

impl Default for ProxyMode {
    fn default() -> Self {
        ProxyMode::WgChainWarp
    }
}

impl ProxyMode {
    pub fn description(&self) -> &'static str {
        match self {
            ProxyMode::WgChainWarp => "WireGuard 链式 WARP (WG -> WARP)",
            ProxyMode::SocksChainWarp => "Socks5 链式 WARP (Socks5 -> WARP)",
            ProxyMode::StandaloneWg => "单独 WireGuard 出站 (无 WARP)",
            ProxyMode::StandaloneSocks => "单独 Socks5 代理出站 (无 WARP)",
            ProxyMode::StandaloneWarp => "单独 Cloudflare WARP 出站",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ParsedNodes {
    pub vpn1: Option<WgConfig>,
    pub vpn2: Option<WgConfig>,
    pub socks5: Option<Socks5Config>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpnNodeConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub wireguard_config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default = "default_true")]
    pub proxy_host_outbound: bool,

    #[serde(default = "default_true")]
    pub proxy_forwarded_outbound: bool,

    #[serde(default = "default_true")]
    pub preserve_inbound_connections: bool,

    #[serde(default = "default_connection_mark")]
    pub connection_mark: String,

    #[serde(default)]
    pub forwarded_subnets: Vec<String>,

    #[serde(default)]
    pub exclude_destinations: Vec<String>,

    #[serde(default)]
    pub ipv6: bool,
}

fn default_true() -> bool {
    true
}

fn default_connection_mark() -> String {
    "0x88".to_string()
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            proxy_host_outbound: true,
            proxy_forwarded_outbound: true,
            preserve_inbound_connections: true,
            connection_mark: default_connection_mark(),
            forwarded_subnets: vec![],
            exclude_destinations: vec![],
            ipv6: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// "chain", "physical", or "custom"
    #[serde(default = "default_dns_mode")]
    pub mode: String,

    #[serde(default)]
    pub custom_servers: Vec<String>,
}

fn default_dns_mode() -> String {
    "chain".to_string()
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: default_dns_mode(),
            custom_servers: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProxyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub mode: ProxyMode,

    #[serde(default)]
    pub uplink_interface: Option<String>,

    #[serde(default)]
    pub vpn1: VpnNodeConfig,

    #[serde(default)]
    pub vpn2: VpnNodeConfig,

    #[serde(default)]
    pub socks5: Option<Socks5Config>,

    #[serde(default)]
    pub routing: RoutingConfig,

    #[serde(default)]
    pub dns: DnsConfig,
}

impl ChainProxyConfig {
    /// Parse and validate nodes according to current ProxyMode
    pub fn parse_and_validate(&self) -> Result<ParsedNodes> {
        let mut parsed = ParsedNodes::default();

        match self.mode {
            ProxyMode::WgChainWarp => {
                let v1 = parse_wireguard_ini(&self.vpn1.wireguard_config)
                    .map_err(|e| ChainError::ValidationError(format!("入口 WireGuard ({}): {}", self.vpn1.name, e)))?;
                if v1.peers.first().and_then(|p| p.endpoint.as_ref()).is_none() {
                    return Err(ChainError::ValidationError(
                        format!("入口 WireGuard ({}) Peer 必须指定 Endpoint (host:port)", self.vpn1.name)
                    ));
                }
                let v2 = parse_wireguard_ini(&self.vpn2.wireguard_config)
                    .map_err(|e| ChainError::ValidationError(format!("出口 WARP ({}): {}", self.vpn2.name, e)))?;
                if v2.peers.first().and_then(|p| p.endpoint.as_ref()).is_none() {
                    return Err(ChainError::ValidationError(
                        format!("出口 WARP ({}) Peer 必须指定 Endpoint (host:port)", self.vpn2.name)
                    ));
                }
                parsed.vpn1 = Some(v1);
                parsed.vpn2 = Some(v2);
            }
            ProxyMode::SocksChainWarp => {
                let s5 = self.socks5.as_ref().ok_or_else(|| {
                    ChainError::ValidationError("当前工作模式为 Socks5 链式 WARP，但未配置 Socks5 入口节点".to_string())
                })?;
                if s5.server.is_empty() || s5.port == 0 {
                    return Err(ChainError::ValidationError("Socks5 代理服务器地址或端口无效".to_string()));
                }
                let v2 = parse_wireguard_ini(&self.vpn2.wireguard_config)
                    .map_err(|e| ChainError::ValidationError(format!("出口 WARP ({}): {}", self.vpn2.name, e)))?;
                if v2.peers.first().and_then(|p| p.endpoint.as_ref()).is_none() {
                    return Err(ChainError::ValidationError(
                        format!("出口 WARP ({}) Peer 必须指定 Endpoint (host:port)", self.vpn2.name)
                    ));
                }
                parsed.socks5 = Some(s5.clone());
                parsed.vpn2 = Some(v2);
            }
            ProxyMode::StandaloneWg => {
                let v1 = parse_wireguard_ini(&self.vpn1.wireguard_config)
                    .map_err(|e| ChainError::ValidationError(format!("WireGuard ({}): {}", self.vpn1.name, e)))?;
                if v1.peers.first().and_then(|p| p.endpoint.as_ref()).is_none() {
                    return Err(ChainError::ValidationError(
                        format!("WireGuard ({}) Peer 必须指定 Endpoint (host:port)", self.vpn1.name)
                    ));
                }
                parsed.vpn1 = Some(v1);
            }
            ProxyMode::StandaloneSocks => {
                let s5 = self.socks5.as_ref().ok_or_else(|| {
                    ChainError::ValidationError("当前工作模式为单独 Socks5 代理出站，但未配置 Socks5 节点".to_string())
                })?;
                if s5.server.is_empty() || s5.port == 0 {
                    return Err(ChainError::ValidationError("Socks5 代理服务器地址或端口无效".to_string()));
                }
                parsed.socks5 = Some(s5.clone());
            }
            ProxyMode::StandaloneWarp => {
                let v2 = parse_wireguard_ini(&self.vpn2.wireguard_config)
                    .map_err(|e| ChainError::ValidationError(format!("Cloudflare WARP ({}): {}", self.vpn2.name, e)))?;
                if v2.peers.first().and_then(|p| p.endpoint.as_ref()).is_none() {
                    return Err(ChainError::ValidationError(
                        format!("Cloudflare WARP ({}) Peer 必须指定 Endpoint (host:port)", self.vpn2.name)
                    ));
                }
                parsed.vpn2 = Some(v2);
            }
        }

        // Validate forwarded subnets
        for subnet in &self.routing.forwarded_subnets {
            subnet.parse::<IpNet>().map_err(|e| {
                ChainError::ValidationError(format!("Invalid forwarded_subnet '{}': {}", subnet, e))
            })?;
        }

        // Validate exclude destinations
        for dest in &self.routing.exclude_destinations {
            dest.parse::<IpNet>().map_err(|e| {
                ChainError::ValidationError(format!("Invalid exclude_destination '{}': {}", dest, e))
            })?;
        }

        Ok(parsed)
    }

    /// Redacted copy of config safe for public logging and API responses
    pub fn redacted(&self) -> Self {
        let mut copy = self.clone();
        if let Ok(p1) = parse_wireguard_ini(&self.vpn1.wireguard_config) {
            copy.vpn1.wireguard_config = format!(
                "[Interface]\nPrivateKey = ********\nAddress = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\n",
                p1.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "),
                p1.peers.first().map(|p| p.public_key.as_str()).unwrap_or(""),
                p1.peers.first().and_then(|p| p.endpoint.as_ref()).map(|e| e.to_string()).unwrap_or_default(),
            );
        } else if !self.vpn1.wireguard_config.is_empty() {
            copy.vpn1.wireguard_config = "********".to_string();
        }

        if let Ok(p2) = parse_wireguard_ini(&self.vpn2.wireguard_config) {
            copy.vpn2.wireguard_config = format!(
                "[Interface]\nPrivateKey = ********\nAddress = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\n",
                p2.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "),
                p2.peers.first().map(|p| p.public_key.as_str()).unwrap_or(""),
                p2.peers.first().and_then(|p| p.endpoint.as_ref()).map(|e| e.to_string()).unwrap_or_default(),
            );
        } else if !self.vpn2.wireguard_config.is_empty() {
            copy.vpn2.wireguard_config = "********".to_string();
        }

        if let Some(ref mut s5) = copy.socks5 {
            if s5.password.is_some() {
                s5.password = Some("********".to_string());
            }
        }

        copy
    }
}

