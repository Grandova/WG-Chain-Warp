use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    Starting,
    Running,
    Degraded,
    RollingBack,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalHopStatus {
    pub interface: String,
    pub ip_addresses: Vec<String>,
    pub gateway: Option<String>,
    pub status: String, // "UP", "DOWN"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnHopStatus {
    pub name: String,
    pub endpoint: String,
    pub config_valid: bool,
    pub reachable: bool,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_ms: Option<u64>,
    pub status: String, // "OK", "ERROR", "UNTESTED"
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalHopStatus {
    pub internet_ok: bool,
    pub exit_ip: Option<String>,
    pub exit_country: Option<String>,
    pub exit_isp: Option<String>,
    pub latency_ms: Option<u64>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    pub state: ServiceState,
    pub active_config_version: Option<String>,
    pub uptime_seconds: u64,
    pub physical: PhysicalHopStatus,
    pub vpn1: VpnHopStatus,
    pub vpn2: VpnHopStatus,
    pub final_hop: FinalHopStatus,
    pub chain_visual: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestReport {
    pub physical: VpnHopStatus,
    pub vpn1: VpnHopStatus,
    pub vpn2: VpnHopStatus,
    pub final_exit: FinalHopStatus,
    pub success: bool,
}
