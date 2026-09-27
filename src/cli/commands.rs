use crate::engine::transaction::ChainEngine;
use crate::error::{ChainError, Result};
use crate::health::diagnose::SystemDiagnostician;
use crate::model::config::ChainProxyConfig;
use crate::model::state::ChainStatus;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub const DEFAULT_API_ADDR: &str = "127.0.0.1:8880";

#[derive(Parser, Debug)]
#[command(name = "chainproxy", author = "Antigravity", version = "1.0.0", about = "Linux Chained WireGuard VPN & Proxy Daemon")]
pub struct Cli {
    #[arg(short, long, default_value = DEFAULT_API_ADDR, global = true)]
    pub api: String,

    #[arg(long, default_value = "/var/lib/chainproxy", global = true)]
    pub data_dir: PathBuf,

    #[arg(long, default_value = "sing-box", global = true)]
    pub singbox: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 打开交互式中文管理面板 (Chinese Interactive Menu)
    Menu,
    /// 自动向 Cloudflare 注册并输出 WARP WireGuard 配置
    WarpReg,
    /// Start daemon background service (runs API server and supervisor)
    Daemon {
        #[arg(long, default_value = "30")]
        watchdog_timeout: u64,
    },
    /// Show current chain proxy status and hop health
    Status,
    /// Validate WireGuard configs and chain configuration file
    Validate {
        /// Path to JSON configuration file
        config: PathBuf,
    },
    /// Transactionally apply new chain configuration
    Apply {
        /// Path to JSON configuration file
        config: PathBuf,
    },
    /// Start the proxy service
    Start,
    /// Stop the proxy service and restore original network
    Stop,
    /// Restart the proxy service
    Restart,
    /// Trigger per-hop link and connectivity tests
    Test,
    /// Rollback to previous configuration version
    Rollback,
    /// View recent logs
    Logs,
    /// Generate sanitized system diagnostic report
    Diagnose,
}

pub struct CliHandler {
    api_url: String,
}

impl CliHandler {
    pub fn new(api: &str) -> Self {
        let url = if api.starts_with("http://") || api.starts_with("https://") {
            api.to_string()
        } else {
            format!("http://{}", api)
        };
        Self { api_url: url }
    }

    pub async fn run_client_command(&self, cmd: &Commands, singbox_bin: &str) -> Result<()> {
        let client = reqwest::Client::new();

        match cmd {
            Commands::Status => {
                let url = format!("{}/api/v1/status", self.api_url);
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let json: serde_json::Value = resp.json().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                        if let Some(data) = json.get("data") {
                            let status: ChainStatus = serde_json::from_value(data.clone())?;
                            println!("=== CHAINPROXY STATUS ===");
                            println!("State: {:?}", status.state);
                            println!("Active Version: {}", status.active_config_version.unwrap_or_else(|| "none".to_string()));
                            println!("Uptime: {} seconds", status.uptime_seconds);
                            println!("Topology: {}", status.chain_visual);
                            println!("Physical Uplink: {} ({:?}) - {}", status.physical.interface, status.physical.gateway, status.physical.status);
                            println!("VPN 1 ({}): {}", status.vpn1.name, status.vpn1.status);
                            println!("VPN 2 ({}): {}", status.vpn2.name, status.vpn2.status);
                            println!("Internet Exit: {}", status.final_hop.status);
                        } else {
                            println!("{}", serde_json::to_string_pretty(&json)?);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to connect to chainproxy daemon at {}: {}", self.api_url, e);
                        eprintln!("Tip: Ensure 'chainproxy daemon' or systemd service 'chainproxy' is running.");
                    }
                }
            }
            Commands::Validate { config } => {
                let content = fs::read_to_string(config)?;
                let parsed_cfg: ChainProxyConfig = serde_json::from_str(&content)?;
                match parsed_cfg.parse_and_validate() {
                    Ok((v1, v2)) => {
                        println!("Configuration is VALID!");
                        println!("VPN1 ({}): {} addresses, peer endpoint: {:?}", parsed_cfg.vpn1.name, v1.interface.addresses.len(), v1.peers[0].endpoint);
                        println!("VPN2 ({}): {} addresses, peer endpoint: {:?}", parsed_cfg.vpn2.name, v2.interface.addresses.len(), v2.peers[0].endpoint);
                    }
                    Err(e) => {
                        eprintln!("Validation FAILED: {}", e);
                    }
                }
            }
            Commands::Apply { config } => {
                let content = fs::read_to_string(config)?;
                let parsed_cfg: ChainProxyConfig = serde_json::from_str(&content)?;
                let url = format!("{}/api/v1/config/apply", self.api_url);
                let payload = serde_json::json!({ "config": parsed_cfg });
                let resp = client.post(&url).json(&payload).send().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp.json().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Start => {
                let url = format!("{}/api/v1/start", self.api_url);
                let resp = client.post(&url).send().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp.json().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Stop => {
                let url = format!("{}/api/v1/stop", self.api_url);
                let resp = client.post(&url).send().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp.json().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Restart => {
                let url = format!("{}/api/v1/restart", self.api_url);
                let resp = client.post(&url).send().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp.json().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Test => {
                let url = format!("{}/api/v1/config/test", self.api_url);
                let resp = client.post(&url).send().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp.json().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Rollback => {
                let url = format!("{}/api/v1/rollback", self.api_url);
                let resp = client.post(&url).send().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp.json().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Logs => {
                let url = format!("{}/api/v1/logs", self.api_url);
                let resp = client.get(&url).send().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp.json().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                if let Some(logs) = json.get("data").and_then(|d| d.as_str()) {
                    println!("{}", logs);
                } else {
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
            }
            Commands::Diagnose => {
                let report = SystemDiagnostician::generate_report(singbox_bin);
                println!("{}", report);
            }
            Commands::Menu => {
                let menu = crate::cli::menu::ConsoleMenu::new(&self.api_url, PathBuf::from("/var/lib/chainproxy"), singbox_bin);
                menu.run().await?;
            }
            Commands::WarpReg => {
                println!("正在连接 Cloudflare API 自动注册 WARP 设备...");
                match crate::wireguard::WarpRegistrar::register_warp().await {
                    Ok(res) => {
                        println!("✅ 注册成功！分配 IPv4: {}, IPv6: {:?}", res.address_v4, res.address_v6);
                        println!("==================== 生成的 WARP 配置 ====================");
                        println!("{}", res.wireguard_config);
                        println!("==========================================================");
                    }
                    Err(e) => {
                        eprintln!("❌ 注册失败: {}", e);
                    }
                }
            }
            Commands::Daemon { .. } => unreachable!(),
        }

        Ok(())
    }

    pub async fn run_daemon(
        api_addr: &str,
        data_dir: PathBuf,
        singbox_bin: &str,
        watchdog_timeout: u64,
    ) -> Result<()> {
        info!("Starting chainproxy daemon on {}", api_addr);
        if let Err(e) = fs::create_dir_all(&data_dir) {
            eprintln!("Notice creating data_dir {:?}: {}", data_dir, e);
        }

        let engine = Arc::new(Mutex::new(ChainEngine::new(&data_dir, singbox_bin)));
        engine.lock().await.set_watchdog_timeout(watchdog_timeout);

        let app = crate::api::create_router(engine, None);

        let listener = tokio::net::TcpListener::bind(api_addr)
            .await
            .map_err(|e| ChainError::NetworkError(format!("Failed to bind to {}: {}", api_addr, e)))?;

        info!("chainproxy REST API listening on {}", api_addr);
        axum::serve(listener, app)
            .await
            .map_err(|e| ChainError::SystemError(format!("Server error: {}", e)))?;

        Ok(())
    }
}
