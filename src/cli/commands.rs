use crate::engine::transaction::ChainEngine;
use crate::error::{ChainError, Result};
use crate::model::panel::PanelSetting;
use crate::model::state::ChainStatus;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub const DEFAULT_API_ADDR: &str = "127.0.0.1:8880";

#[derive(Parser, Debug)]
#[command(
    name = "sooya",
    author = "Sooya",
    version = env!("CARGO_PKG_VERSION"),
    about = "Sooya - Lightweight Linux Chained WireGuard & WARP Proxy Panel"
)]
pub struct Cli {
    #[arg(short, long, default_value = DEFAULT_API_ADDR, global = true)]
    pub api: String,

    #[arg(long, default_value = "/var/lib/sooya", global = true)]
    pub data_dir: PathBuf,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 显示 Sooya 管理菜单
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
    /// 启动 Sooya 面板与服务
    Start,
    /// 停止 Sooya 面板与代理服务并恢复原网络
    Stop,
    /// 重启 Sooya 面板与服务
    Restart,
    /// 查看 Sooya 运行状态
    Status,
    /// 设置 Sooya 开机自启
    Enable,
    /// 取消 Sooya 开机自启
    Disable,
    /// 查看 Sooya 运行日志
    #[command(visible_alias = "log")]
    Logs,
    /// 在线更新 Sooya 至最新版本
    Update,
    /// 卸载 Sooya 面板与服务
    Uninstall,
    /// 启动后台守护服务 (Web 面板与 API)
    Daemon,
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

    pub async fn run_client_command(&self, cmd: &Commands, data_dir: &Path) -> Result<()> {
        let client = reqwest::Client::new();
        let auth_token = PanelSetting::load_or_default(data_dir).session_secret;

        match cmd {
            Commands::Setting { port, listen, username, password, base_path, reset, show } => {
                let mut panel = PanelSetting::load_or_default(data_dir);
                if *reset {
                    let def = PanelSetting::default();
                    panel.listen = def.listen;
                    panel.port = def.port;
                    panel.base_path = def.base_path;
                    panel.username = def.username;
                    panel.password = def.password;
                    panel.rotate_session_secret();
                }

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
                    println!("✅ Sooya Web 面板设置已保存更新！");
                }

                if *show || modified {
                    println!("================ Sooya Web 面板当前配置 ================");
                    println!("实例标识 : {}", panel.instance_id);
                    println!("监听地址 : {}", panel.listen);
                    println!("监听端口 : {}", panel.port);
                    println!("根 路 径 : {}", panel.base_path);
                    println!("用 户 名 : {}", panel.username);
                    println!("========================================================");
                }
            }
            Commands::Status => {
                let url = format!("{}/api/v1/status", self.api_url);
                match client.get(&url).header("x-sooya-token", &auth_token).send().await {
                    Ok(resp) => {
                        let json: serde_json::Value = resp
                            .json()
                            .await
                            .map_err(|e| ChainError::NetworkError(e.to_string()))?;
                        if let Some(data) = json.get("data") {
                            let status: ChainStatus = serde_json::from_value(data.clone())?;
                            println!("=== SOOYA STATUS ===");
                            println!("State         : {:?}", status.state);
                            println!("Active Version: {}", status.active_config_version.unwrap_or_else(|| "none".to_string()));
                            println!("Uptime        : {} seconds", status.uptime_seconds);
                            println!("Topology      : {}", status.chain_visual);
                            println!("Physical Uplink: {} ({:?}) - {}", status.physical.interface, status.physical.gateway, status.physical.status);
                            println!("Hop 1 ({})    : {}", status.vpn1.name, status.vpn1.status);
                            println!("Hop 2 ({})    : {}", status.vpn2.name, status.vpn2.status);
                            println!("Internet Exit : {}", status.final_hop.status);
                        } else {
                            println!("{}", serde_json::to_string_pretty(&json)?);
                        }
                    }
                    Err(e) => {
                        eprintln!("未能连接 Sooya 守护进程 ({}): {}", self.api_url, e);
                        eprintln!("提示: 请执行 'sooya start' 或 'systemctl start sooya' 启动服务。");
                    }
                }
            }
            Commands::Start => {
                let _ = Command::new("systemctl").args(["start", "sooya"]).status();
                println!("✅ Sooya 服务已启动");
            }
            Commands::Stop => {
                let _ = client
                    .post(format!("{}/api/v1/stop", self.api_url))
                    .header("x-sooya-token", &auth_token)
                    .send()
                    .await;
                println!("✅ 代理链路已停止，宿主机网络已恢复");
            }
            Commands::Restart => {
                let _ = Command::new("systemctl").args(["restart", "sooya"]).status();
                println!("✅ Sooya 服务已重启");
            }
            Commands::Enable => {
                let _ = Command::new("systemctl").args(["enable", "sooya"]).status();
                println!("✅ 已设置 Sooya 开机自启");
            }
            Commands::Disable => {
                let _ = Command::new("systemctl").args(["disable", "sooya"]).status();
                println!("✅ 已取消 Sooya 开机自启");
            }
            Commands::Update => {
                println!("正在拉取最新版本并更新 Sooya...");
                let _ = Command::new("bash")
                    .args([
                        "-c",
                        "curl -fsSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh | bash",
                    ])
                    .status();
            }
            Commands::Uninstall => {
                let _ = client
                    .post(format!("{}/api/v1/stop", self.api_url))
                    .header("x-sooya-token", &auth_token)
                    .send()
                    .await;
                let _ = Command::new("systemctl").args(["stop", "sooya"]).status();
                let _ = Command::new("systemctl").args(["disable", "sooya"]).status();
                let _ = fs::remove_file("/etc/systemd/system/sooya.service");
                let _ = Command::new("systemctl").arg("daemon-reload").status();
                let _ = fs::remove_dir_all("/usr/local/sooya");
                let _ = fs::remove_file("/usr/bin/sooya");
                let _ = fs::remove_file("/usr/local/bin/sooya");
                println!("✅ Sooya 已卸载完成 (配置文件保留在 /var/lib/sooya)");
            }
            Commands::Logs => {
                let url = format!("{}/api/v1/logs", self.api_url);
                if let Ok(resp) = client.get(&url).header("x-sooya-token", &auth_token).send().await {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        if let Some(logs) = json.get("data").and_then(|d| d.as_str()) {
                            println!("{}", logs);
                            return Ok(());
                        }
                    }
                }
                let _ = Command::new("journalctl").args(["-u", "sooya", "-n", "50", "--no-pager"]).status();
            }
            Commands::Menu => {
                let menu = crate::cli::menu::ConsoleMenu::new(&self.api_url, data_dir.to_path_buf());
                menu.run().await?;
            }
            Commands::Daemon => unreachable!(),
        }

        Ok(())
    }

    pub async fn run_daemon(api_addr: &str, data_dir: PathBuf) -> Result<()> {
        let _ = fs::create_dir_all(&data_dir);
        let panel = PanelSetting::load_or_default(&data_dir);
        let panel_bind = panel.bind_addr();

        let engine = Arc::new(Mutex::new(ChainEngine::new(&data_dir)));
        let app = crate::api::create_router(engine);

        if api_addr != panel_bind {
            if let Ok(local_listener) = tokio::net::TcpListener::bind(api_addr).await {
                info!("Sooya local control API listening on {}", api_addr);
                let app_clone = app.clone();
                tokio::spawn(async move {
                    let _ = axum::serve(local_listener, app_clone).await;
                });
            }
        }

        info!("Starting Sooya Web Console on http://{}{}", panel_bind, panel.base_path);
        let listener = match tokio::net::TcpListener::bind(&panel_bind).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Warning: failed to bind web panel on {} ({}), falling back to {}", panel_bind, e, api_addr);
                tokio::net::TcpListener::bind(api_addr)
                    .await
                    .map_err(|e2| ChainError::NetworkError(format!("Failed to bind to {}: {}", api_addr, e2)))?
            }
        };

        axum::serve(listener, app)
            .await
            .map_err(|e| ChainError::SystemError(format!("Server error: {}", e)))?;

        Ok(())
    }
}
