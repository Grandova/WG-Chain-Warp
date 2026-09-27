use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgEndpoint {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for WgEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') && !self.host.starts_with('[') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgInterface {
    pub private_key: String,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
    /// Script hooks found in config (PostUp, PreUp, etc.) - stored for user reference ONLY, NEVER executed!
    pub ignored_scripts: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgPeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<WgEndpoint>,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgConfig {
    pub interface: WgInterface,
    pub peers: Vec<WgPeer>,
}

impl WgConfig {
    /// Return a sanitized copy with PrivateKey and PresharedKey masked
    pub fn redacted(&self) -> Self {
        let mut copy = self.clone();
        copy.interface.private_key = "********".to_string();
        for peer in &mut copy.peers {
            if peer.preshared_key.is_some() {
                peer.preshared_key = Some("********".to_string());
            }
        }
        copy
    }
}
