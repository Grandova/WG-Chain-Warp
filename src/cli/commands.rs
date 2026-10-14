use crate::engine::transaction::ChainEngine;
use crate::error::{ChainError, Result};
use crate::health::diagnose::SystemDiagnostician;
use crate::model::config::ChainProxyConfig;
use crate::model::panel::PanelSetting;
use crate::model::state::ChainStatus;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub const DEFAULT_API_ADDR: &str = "127.0.0.1:8880";

#[derive(Parser, Debug)]
#[command(
    name = "chainproxy",
    author = "Antigravity",
    version = env!("CARGO_PKG_VERSION"),
    about = "Linux Chained WireGuard VPN & Web Management Panel"
)]
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
    /// 打开面板终端管理菜单 (x-ui 风格服务与面板管理菜单)
    Menu,
    /// 修改或查看 Web 面板设置 (端口、登录用户名、密码、根路径)
    Setting {
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        base_path: Option<String>,
        #[arg(long)]
        reset: bool,
        #[arg(long)]
        show: bool,
    },
    /// 自动向 Cloudflare 注册并输出 WARP WireGuard 配置
    WarpReg,
    /// Start daemon background service (runs Web Panel and API server)
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

    pub async fn run_client_command(
        &self,
        cmd: &Commands,
        singbox_bin: &str,
        data_dir: &std::path::Path,
    ) -> Result<()> {
        let client = reqwest::Client::new();

        match cmd {
            Commands::Setting {
                port,
                listen,
                username,
                password,
                base_path,
                reset,
                show,
            } => {
                let mut panel = if *reset {
                    PanelSetting::default()
                } else {
                    PanelSetting::load_or_default(data_dir)
                };

                let mut modified = *reset;
                if let Some(p) = port {
                    panel.port = *p;
                    modified = true;
                }
                if let Some(l) = listen {
                    panel.listen = l.clone();
                    modified = true;
                }
                if let Some(u) = username {
                    panel.username = u.clone();
                    panel.rotate_session_secret();
                    modified = true;
                }
                if let Some(pw) = password {
                    panel.password = pw.clone();
                    panel.rotate_session_secret();
                    modified = true;
                }
                if let Some(bp) = base_path {
                    panel.base_path = bp.clone();
                    modified = true;
                }

                if modified {
                    panel.normalize();
                    panel.validate()?;
                    panel.save(data_dir)?;
                    println!("✅ Web 面板设置已保存更新！");
                }

                if *show || modified {
                    println!("================ Web 面板当前配置 ================");
                    println!("监听地址 : {}", panel.listen);
                    println!("监听端口 : {}", panel.port);
                    println!("根 路 径 : {}", panel.base_path);
                    println!("用 户 名 : {}", panel.username);
                    println!("==================================================");
                }
            }
            Commands::Status => {
                let url = format!("{}/api/v1/status", self.api_url);
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let json: serde_json::Value = resp
                            .json()
                            .await
                            .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                        if let Some(data) = json.get("data") {
                            let status: ChainStatus = serde_json::from_value(data.clone())?;
                            println!("=== CHAINPROXY STATUS ===");
                            println!("State: {:?}", status.state);
                            println!(
                                "Active Version: {}",
                                status
                                    .active_config_version
                                    .unwrap_or_else(|| "none".to_string())
                            );
                            println!("Uptime: {} seconds", status.uptime_seconds);
                            println!("Topology: {}", status.chain_visual);
                            println!(
                                "Physical Uplink: {} ({:?}) - {}",
                                status.physical.interface,
                                status.physical.gateway,
                                status.physical.status
                            );
                            println!("VPN 1 ({}): {}", status.vpn1.name, status.vpn1.status);
                            println!("VPN 2 ({}): {}", status.vpn2.name, status.vpn2.status);
                            println!("Internet Exit: {}", status.final_hop.status);
                        } else {
                            println!("{}", serde_json::to_string_pretty(&json)?);
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to connect to chainproxy daemon at {}: {}",
                            self.api_url, e
                        );
                        eprintln!(
                            "Tip: Ensure 'chainproxy daemon' or systemd service 'chainproxy' is running."
                        );
                    }
                }
            }
            Commands::Validate { config } => {
                let content = fs::read_to_string(config)?;
                let parsed_cfg: ChainProxyConfig = serde_json::from_str(&content)?;
                match parsed_cfg.parse_and_validate() {
                    Ok(parsed) => {
                        println!("Configuration is VALID! Mode: {:?}", parsed_cfg.mode);
                        if let Some(v1) = parsed.vpn1 {
                            println!(
                                "VPN1 ({}): {} addresses, peer endpoint: {:?}",
                                parsed_cfg.vpn1.name,
                                v1.interface.addresses.len(),
                                v1.peers.first().and_then(|p| p.endpoint.as_ref())
                            );
                        }
                        if let Some(v2) = parsed.vpn2 {
                            println!(
                                "VPN2 ({}): {} addresses, peer endpoint: {:?}",
                                parsed_cfg.vpn2.name,
                                v2.interface.addresses.len(),
                                v2.peers.first().and_then(|p| p.endpoint.as_ref())
                            );
                        }
                        if let Some(s5) = parsed.socks5 {
                            println!("Socks5 Proxy: {}", s5.redacted_string());
                        }
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
                let resp = client
                    .post(&url)
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Start => {
                let url = format!("{}/api/v1/start", self.api_url);
                let resp = client
                    .post(&url)
                    .send()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Stop => {
                let url = format!("{}/api/v1/stop", self.api_url);
                let resp = client
                    .post(&url)
                    .send()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Restart => {
                let url = format!("{}/api/v1/restart", self.api_url);
                let resp = client
                    .post(&url)
                    .send()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Test => {
                let url = format!("{}/api/v1/config/test", self.api_url);
                let resp = client
                    .post(&url)
                    .send()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Rollback => {
                let url = format!("{}/api/v1/rollback", self.api_url);
                let resp = client
                    .post(&url)
                    .send()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            Commands::Logs => {
                let url = format!("{}/api/v1/logs", self.api_url);
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                let json: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ChainError::NetworkError(e.to_string()))?;
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
                let menu = crate::cli::menu::ConsoleMenu::new(
                    &self.api_url,
                    data_dir.to_path_buf(),
                    singbox_bin,
                );
                menu.run().await?;
            }
            Commands::WarpReg => {
                println!("正在连接 Cloudflare API 自动注册 WARP 设备...");
                match crate::wireguard::WarpRegistrar::register_warp().await {
                    Ok(res) => {
                        println!(
                            "✅ 注册成功！分配 IPv4: {}, IPv6: {:?}",
                            res.address_v4, res.address_v6
                        );
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
        if let Err(e) = fs::create_dir_all(&data_dir) {
            eprintln!("Notice creating data_dir {:?}: {}", data_dir, e);
        }

        let panel = PanelSetting::load_or_default(&data_dir);
        let panel_bind = panel.bind_addr();

        let engine = Arc::new(Mutex::new(ChainEngine::new(&data_dir, singbox_bin)));
        engine.lock().await.set_watchdog_timeout(watchdog_timeout);

        let app = crate::api::create_router(engine, None);

        // If local API addr (e.g. 127.0.0.1:8880) differs from panel_bind (e.g. 0.0.0.0:54321),
        // bind both so CLI commands on 127.0.0.1:8880 and external Web Console on panel_bind both work.
        if api_addr != panel_bind {
            if let Ok(local_listener) = tokio::net::TcpListener::bind(api_addr).await {
                info!("chainproxy local control API listening on {}", api_addr);
                let app_clone = app.clone();
                tokio::spawn(async move {
                    let _ = axum::serve(local_listener, app_clone).await;
                });
            }
        }

        info!(
            "Starting chainproxy Web Console on http://{}{}",
            panel_bind, panel.base_path
        );
        let listener = match tokio::net::TcpListener::bind(&panel_bind).await {
            Ok(l) => l,
            Err(e) => {
                // Fallback to api_addr if panel_bind is already bound or unavailable in restricted environment
                eprintln!(
                    "Warning: failed to bind web panel on {} ({}), falling back to {}",
                    panel_bind, e, api_addr
                );
                tokio::net::TcpListener::bind(api_addr).await.map_err(|e2| {
                    ChainError::NetworkError(format!("Failed to bind to {}: {}", api_addr, e2))
                })?
            }
        };

        axum::serve(listener, app)
            .await
            .map_err(|e| ChainError::SystemError(format!("Server error: {}", e)))?;

        Ok(())
    }
}
