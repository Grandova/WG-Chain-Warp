use crate::wireguard::model::WgConfig;
use crate::wireguard::parser::parse_wireguard_ini;
use crate::error::{ChainError, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnNodeConfig {
    pub name: String,
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
    pub uplink_interface: Option<String>,

    pub vpn1: VpnNodeConfig,
    pub vpn2: VpnNodeConfig,

    #[serde(default)]
    pub routing: RoutingConfig,

    #[serde(default)]
    pub dns: DnsConfig,
}

impl ChainProxyConfig {
    /// Parse and validate both VPN configurations
    pub fn parse_and_validate(&self) -> Result<(WgConfig, WgConfig)> {
        let vpn1_parsed = parse_wireguard_ini(&self.vpn1.wireguard_config)
            .map_err(|e| ChainError::ValidationError(format!("VPN1 ({}): {}", self.vpn1.name, e)))?;

        let vpn2_parsed = parse_wireguard_ini(&self.vpn2.wireguard_config)
            .map_err(|e| ChainError::ValidationError(format!("VPN2 ({}): {}", self.vpn2.name, e)))?;

        // Ensure both VPNs have at least one peer with endpoint
        if vpn1_parsed.peers.first().and_then(|p| p.endpoint.as_ref()).is_none() {
            return Err(ChainError::ValidationError(
                format!("VPN1 ({}) peer must specify an Endpoint (host:port)", self.vpn1.name)
            ));
        }

        if vpn2_parsed.peers.first().and_then(|p| p.endpoint.as_ref()).is_none() {
            return Err(ChainError::ValidationError(
                format!("VPN2 ({}) peer must specify an Endpoint (host:port)", self.vpn2.name)
            ));
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

        Ok((vpn1_parsed, vpn2_parsed))
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
        } else {
            copy.vpn1.wireguard_config = "********".to_string();
        }

        if let Ok(p2) = parse_wireguard_ini(&self.vpn2.wireguard_config) {
            copy.vpn2.wireguard_config = format!(
                "[Interface]\nPrivateKey = ********\nAddress = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\n",
                p2.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "),
                p2.peers.first().map(|p| p.public_key.as_str()).unwrap_or(""),
                p2.peers.first().and_then(|p| p.endpoint.as_ref()).map(|e| e.to_string()).unwrap_or_default(),
            );
        } else {
            copy.vpn2.wireguard_config = "********".to_string();
        }

        copy
    }
}
