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
    #[serde(default)]
    pub reserved: [u8; 3],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgPeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<WgEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgConfig {
    pub interface: WgInterface,
    pub peers: Vec<WgPeer>,
}
