use crate::error::{ChainError, Result};
use crate::wireguard::model::WgConfig;
use crate::wireguard::parser::parse_wireguard_ini;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Socks5Config {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl Socks5Config {
    pub fn redacted_string(&self) -> String {
        match (&self.username, &self.password) {
            (Some(u), Some(_)) => format!("socks5://{}:********@{}:{}", u, self.server, self.port),
            (Some(u), None) => format!("socks5://{}@{}:{}", u, self.server, self.port),
            (None, _) => format!("socks5://{}:{}", self.server, self.port),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Socks5User {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Socks5ServerConfig {
    pub listen: std::net::IpAddr,
    pub port: u16,
    pub users: Vec<Socks5User>,
}

impl Socks5ServerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(ChainError::ValidationError(
                "SOCKS5 服务端必须配置有效端口 (1-65535)".to_string(),
            ));
        }
        let mut names = HashSet::new();
        for u in &self.users {
            if u.username.trim().is_empty() && u.password.trim().is_empty() {
                continue;
            }
            if !(1..=255).contains(&u.username.len()) || !(1..=255).contains(&u.password.len()) {
                return Err(ChainError::ValidationError("SOCKS5 用户名、密码必须为 1–255 字节（或全部留空使用免密模式）".to_string()));
            }
            if !names.insert(&u.username) {
                return Err(ChainError::ValidationError("SOCKS5 用户名不能重复".to_string()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    #[default]
    #[serde(alias = "WgChainWarp")]
    WgChainWarp,
    #[serde(alias = "SocksChainWarp")]
    SocksChainWarp,
    #[serde(alias = "StandaloneWg")]
    StandaloneWg,
    #[serde(alias = "StandaloneSocks")]
    StandaloneSocks,
    #[serde(alias = "StandaloneWarp")]
    StandaloneWarp,
    #[serde(alias = "Socks5Server")]
    Socks5Server,
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
    pub preserve_inbound_connections: bool,
    #[serde(default = "default_connection_mark")]
    pub connection_mark: String,
    #[serde(default)]
    pub exclude_destinations: Vec<String>,
    #[serde(default)]
    pub ipv6: bool,
}

fn default_true() -> bool { true }
fn default_connection_mark() -> String { "0x88".to_string() }

impl RoutingConfig {
    pub fn inbound_mark(&self) -> Result<u32> {
        use crate::network::iproute::{MARK_HOST_PROXY, MARK_PHYSICAL_DIRECT};
        let value = self
            .connection_mark
            .strip_prefix("0x")
            .map(|hex| u32::from_str_radix(hex, 16))
            .unwrap_or_else(|| self.connection_mark.parse());
        match value {
            Ok(mark) if mark != 0 && mark & (MARK_PHYSICAL_DIRECT | MARK_HOST_PROXY) == 0 => Ok(mark),
            _ => Err(ChainError::ValidationError(
                "connection_mark must be nonzero and disjoint from physical/host marks".to_string(),
            )),
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            proxy_host_outbound: true,
            preserve_inbound_connections: true,
            connection_mark: default_connection_mark(),
            exclude_destinations: vec![],
            ipv6: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainProxyConfig {
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
    pub socks5_server: Option<Socks5ServerConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
}

impl ChainProxyConfig {
    fn parse_wg(node: &VpnNodeConfig, label: &str) -> Result<WgConfig> {
        let wg = parse_wireguard_ini(&node.wireguard_config).map_err(|e| {
            ChainError::ValidationError(format!("{} ({}): {}", label, node.name, e))
        })?;
        if wg.peers.first().and_then(|p| p.endpoint.as_ref()).is_none() {
            return Err(ChainError::ValidationError(format!(
                "{} ({}) Peer 必须指定 Endpoint (host:port)",
                label, node.name
            )));
        }
        Ok(wg)
    }

    fn validate_socks5(&self) -> Result<Socks5Config> {
        let s5 = self.socks5.as_ref().ok_or_else(|| {
            ChainError::ValidationError("未配置 SOCKS5 代理节点".to_string())
        })?;
        if s5.server.is_empty() || s5.port == 0 {
            return Err(ChainError::ValidationError("SOCKS5 服务器地址或端口无效".to_string()));
        }
        Ok(s5.clone())
    }

    pub fn parse_and_validate(&self) -> Result<ParsedNodes> {
        self.routing.inbound_mark()?;
        let mut parsed = ParsedNodes::default();
        match self.mode {
            ProxyMode::Socks5Server => {
                self.socks5_server
                    .as_ref()
                    .ok_or_else(|| ChainError::ValidationError("尚未配置 SOCKS5 服务端".to_string()))?
                    .validate()?;
            }
            ProxyMode::WgChainWarp => {
                parsed.vpn1 = Some(Self::parse_wg(&self.vpn1, "入口 WireGuard")?);
                parsed.vpn2 = Some(Self::parse_wg(&self.vpn2, "出口 WARP")?);
            }
            ProxyMode::SocksChainWarp => {
                parsed.socks5 = Some(self.validate_socks5()?);
                parsed.vpn2 = Some(Self::parse_wg(&self.vpn2, "出口 WARP")?);
            }
            ProxyMode::StandaloneWg => {
                parsed.vpn1 = Some(Self::parse_wg(&self.vpn1, "WireGuard")?);
            }
            ProxyMode::StandaloneSocks => {
                parsed.socks5 = Some(self.validate_socks5()?);
            }
            ProxyMode::StandaloneWarp => {
                parsed.vpn2 = Some(Self::parse_wg(&self.vpn2, "Cloudflare WARP")?);
            }
        }
        for dest in &self.routing.exclude_destinations {
            dest.parse::<IpNet>().map_err(|e| {
                ChainError::ValidationError(format!("Invalid exclude_destination '{}': {}", dest, e))
            })?;
        }
        Ok(parsed)
    }
}
