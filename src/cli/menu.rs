use crate::error::{ChainError, Result};
use crate::model::panel::PanelSetting;
use crate::model::state::{ChainStatus, ServiceState};
use crate::network::iproute::IpRouteManager;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

pub struct ConsoleMenu {
    api_url: String,
    data_dir: PathBuf,
    client: reqwest::Client,
}

impl ConsoleMenu {
    pub fn new(api_url: &str, data_dir: PathBuf) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            api_url: api_url.to_string(),
            data_dir,
            client,
        }
    }

    pub async fn run(&self) -> Result<()> {
        loop {
            let panel = PanelSetting::load_or_default(&self.data_dir);
            let daemon_status = self.fetch_status().await;
            let host_ip = Self::detect_server_ip();

            self.print_header(&panel, daemon_status.as_ref(), &host_ip);
            self.print_menu_options();

            let choice = self.prompt("\n请输入选择 [0-13]: ")?;
            match choice.trim() {
                "1" => self.update_sooya().await?,
                "2" => self.uninstall_sooya().await?,
                "3" => self.change_credentials().await?,
                "4" => self.reset_panel_settings().await?,
                "5" => self.change_port_and_path().await?,
                "6" => self.show_panel_access_info(&panel, &host_ip)?,
                "7" => self.start_panel_service().await?,
                "8" => self.stop_panel_service().await?,
                "9" => self.restart_panel_service().await?,
                "10" => self.show_detailed_status(daemon_status.as_ref()).await?,
                "11" => self.view_logs().await?,
                "12" => self.set_autostart(true)?,
                "13" => self.set_autostart(false)?,
                "0" | "q" | "exit" => {
                    println!("已退出 Sooya 管理脚本。");
                    break;
                }
                _ => {
                    println!("{}请输入正确的数字 [0-13]{}", RED, RESET);
                    self.pause()?;
                }
            }
        }
        Ok(())
    }

    fn detect_server_ip() -> String {
        if let Ok(up) = IpRouteManager::detect_default_uplink() {
            if let Some(ip) = up.local_ip {
                return ip.to_string();
            }
        }
        "<服务器IP>".to_string()
    }

    fn print_header(&self, panel: &PanelSetting, status: Option<&ChainStatus>, host_ip: &str) {
        println!("\n  {}{}Sooya 面板管理脚本 v{}{}", BOLD, GREEN, env!("CARGO_PKG_VERSION"), RESET);
        let display_ip = if panel.listen == "0.0.0.0" || panel.listen == "::" || panel.listen.is_empty() {
            host_ip
        } else {
            panel.listen.as_str()
        };
        println!("  Web 面板地址: {}{}http://{}:{}{}{}", BOLD, CYAN, display_ip, panel.port, panel.base_path, RESET);
        match status {
            Some(st) => {
                let proxy_badge = match st.state {
                    ServiceState::Running => format!("{}运行中{}", GREEN, RESET),
                    ServiceState::Failed => format!("{}异常{}", RED, RESET),
                    _ => format!("{}待机中{}", YELLOW, RESET),
                };
                println!("  面板状态: {}运行中{}  |  WarpKernel 内核: {}", GREEN, RESET, proxy_badge);
            }
            None => println!("  面板状态: {}未运行{}", RED, RESET),
        }
    }

    fn print_menu_options(&self) {
        println!("  {}0.{} 退出脚本", GREEN, RESET);
        println!("————————————————");
        println!("  {}1.{} 更新 Sooya", GREEN, RESET);
        println!("  {}2.{} 卸载 Sooya", GREEN, RESET);
        println!("————————————————");
        println!("  {}3.{} 重置用户名密码", GREEN, RESET);
        println!("  {}4.{} 重置面板设置", GREEN, RESET);
        println!("  {}5.{} 设置面板端口与根路径", GREEN, RESET);
        println!("  {}6.{} 查看当前面板设置", GREEN, RESET);
        println!("————————————————");
        println!("  {}7.{} 启动 Sooya", GREEN, RESET);
        println!("  {}8.{} 停止 Sooya", GREEN, RESET);
        println!("  {}9.{} 重启 Sooya", GREEN, RESET);
        println!(" {}10.{} 查看 Sooya 状态", GREEN, RESET);
        println!(" {}11.{} 查看 Sooya 日志", GREEN, RESET);
        println!("————————————————");
        println!(" {}12.{} 设置 Sooya 开机自启", GREEN, RESET);
        println!(" {}13.{} 取消 Sooya 开机自启", GREEN, RESET);
    }

    fn auth_token(&self) -> String {
        PanelSetting::load_or_default(&self.data_dir).session_secret
    }

    async fn fetch_status(&self) -> Option<ChainStatus> {
        let resp = self
            .client
            .get(format!("{}/api/v1/status", self.api_url))
            .header("x-sooya-token", self.auth_token())
            .send()
            .await
            .ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        serde_json::from_value(json.get("data")?.clone()).ok()
    }

    async fn update_sooya(&self) -> Result<()> {
        let confirm = self.prompt("\n本功能会强制重装当前最新版，数据不会丢失，是否继续? [y/N]: ")?;
        if confirm.trim().eq_ignore_ascii_case("y") {
            let _ = Command::new("bash")
                .args([
                    "-c",
                    "curl -fsSL https://raw.githubusercontent.com/Grandova/WG-Chain-Warp/main/scripts/install.sh | bash",
                ])
                .status();
            std::process::exit(0);
        }
        self.pause()
    }

    async fn uninstall_sooya(&self) -> Result<()> {
        let confirm = self.prompt("\n确定要卸载面板吗，代理规则也将自动恢复? [y/N]: ")?;
        if confirm.trim().eq_ignore_ascii_case("y") {
            let _ = self
                .client
                .post(format!("{}/api/v1/stop", self.api_url))
                .header("x-sooya-token", self.auth_token())
                .send()
                .await;
            let _ = Command::new("systemctl").args(["stop", "sooya"]).status();
            let _ = Command::new("systemctl").args(["disable", "sooya"]).status();
            let _ = std::fs::remove_file("/etc/systemd/system/sooya.service");
            let _ = Command::new("systemctl").arg("daemon-reload").status();
            let _ = std::fs::remove_dir_all("/usr/local/sooya");
            let _ = std::fs::remove_file("/usr/bin/sooya");
            let _ = std::fs::remove_file("/usr/local/bin/sooya");
            println!("{}✅ 卸载成功！{}", GREEN, RESET);
            std::process::exit(0);
        }
        self.pause()
    }

    async fn start_panel_service(&self) -> Result<()> {
        println!("\n正在启动 Sooya 面板服务...");
        match Command::new("systemctl").args(["start", "sooya"]).status() {
            Ok(s) if s.success() => {
                tokio::time::sleep(Duration::from_millis(600)).await;
                println!("{}✅ Sooya 启动成功！{}", GREEN, RESET);
            }
            _ => println!("{}⚠️ 面板启动失败，请使用日志功能查看原因。{}", RED, RESET),
        }
        self.pause()
    }

    async fn stop_panel_service(&self) -> Result<()> {
        println!("\n正在停止代理链路并恢复宿主机原始网络...");
        let _ = self
            .client
            .post(format!("{}/api/v1/stop", self.api_url))
            .header("x-sooya-token", self.auth_token())
            .send()
            .await;
        println!("正在停止 Sooya 守护服务...");
        let _ = Command::new("systemctl").args(["stop", "sooya"]).status();
        println!("{}✅ 停止成功，原始网络已恢复。{}", GREEN, RESET);
        self.pause()
    }

    async fn restart_panel_service(&self) -> Result<()> {
        println!("\n正在重启 Sooya 面板服务...");
        match Command::new("systemctl").args(["restart", "sooya"]).status() {
            Ok(s) if s.success() => {
                tokio::time::sleep(Duration::from_millis(600)).await;
                println!("{}✅ Sooya 重启成功！{}", GREEN, RESET);
            }
            _ => println!("{}⚠️ 重启失败，请查看运行日志。{}", RED, RESET),
        }
        self.pause()
    }

    async fn show_detailed_status(&self, status: Option<&ChainStatus>) -> Result<()> {
        println!("\n--- [Sooya 面板与服务状态] ---");
        if let Some(st) = status {
            println!("代理引擎状态 : {:?}", st.state);
            println!("持续运行时间 : {} 秒", st.uptime_seconds);
            println!("当前生效版本 : {}", st.active_config_version.as_deref().unwrap_or("无"));
            println!("当前链路拓扑 : {}", st.chain_visual);
            println!("物理出口网卡 : {} (网关: {:?}) [{}]", st.physical.interface, st.physical.gateway, st.physical.status);
            println!("第一跳节点   : {} ({}) [{}]", st.vpn1.name, st.vpn1.endpoint, st.vpn1.status);
            println!("第二跳节点   : {} ({}) [{}]", st.vpn2.name, st.vpn2.endpoint, st.vpn2.status);
        } else {
            println!("{}守护进程当前未运行。{}", YELLOW, RESET);
        }
        if let Ok(out) = Command::new("systemctl").args(["status", "sooya", "--no-pager", "-n", "8"]).output() {
            println!("\n{}", String::from_utf8_lossy(&out.stdout));
        }
        self.pause()
    }

    async fn change_credentials(&self) -> Result<()> {
        let mut panel = PanelSetting::load_or_default(&self.data_dir);
        let new_user = self.prompt(&format!("请设置您的账户名 [默认 {}]: ", panel.username))?;
        let new_pass = self.prompt("请设置您的账户密码: ")?;

        if !new_user.trim().is_empty() {
            panel.username = new_user.trim().to_string();
        }
        if !new_pass.trim().is_empty() {
            panel.password = new_pass.trim().to_string();
        } else {
            println!("{}❌ 密码不能为空，已取消修改。{}", RED, RESET);
            return self.pause();
        }

        panel.rotate_session_secret();
        panel.save(&self.data_dir)?;
        let _ = Command::new("systemctl").args(["restart", "sooya"]).status();
        println!("{}✅ 账户用户名密码设定完成！新用户名: {}{}", GREEN, panel.username, RESET);
        self.pause()
    }

    async fn change_port_and_path(&self) -> Result<()> {
        let mut panel = PanelSetting::load_or_default(&self.data_dir);

        let port_str = self.prompt(&format!("输入面板端口号 (1-65535) [当前: {}]: ", panel.port))?;
        if !port_str.trim().is_empty() {
            match port_str.trim().parse::<u16>() {
                Ok(p) if p > 0 => panel.port = p,
                _ => {
                    println!("{}❌ 端口格式无效，必须在 1 ~ 65535 之间。{}", RED, RESET);
                    return self.pause();
                }
            }
        }

        let bp_str = self.prompt(&format!("输入面板 URL 根路径 [当前: {}]: ", panel.base_path))?;
        if !bp_str.trim().is_empty() {
            panel.base_path = bp_str.trim().to_string();
        }

        panel.normalize();
        panel.save(&self.data_dir)?;
        let _ = Command::new("systemctl").args(["restart", "sooya"]).status();
        let host_ip = Self::detect_server_ip();
        println!("{}✅ 设置端口完毕！新访问地址: http://{}:{}{}{}", GREEN, host_ip, panel.port, panel.base_path, RESET);
        self.pause()
    }

    fn show_panel_access_info(&self, panel: &PanelSetting, host_ip: &str) -> Result<()> {
        println!("\n================ Sooya 当前面板设置 ================");
        println!(" 实例唯一标识 : {}", panel.instance_id);
        println!(" 面板访问地址 : {}http://{}:{}{}{}", GREEN, host_ip, panel.port, panel.base_path, RESET);
        println!(" 面板监听地址 : {}:{}", panel.listen, panel.port);
        println!(" 面板根路径   : {}", panel.base_path);
        println!(" 登录用户名   : {}", panel.username);
        println!(" 登录密  码   : {}", panel.password);
        println!("====================================================");
        self.pause()
    }

    async fn reset_panel_settings(&self) -> Result<()> {
        let confirm = self.prompt("\n确定要将所有面板设置重置为默认值吗（端口 54321，账号密码 admin）？[y/N]: ")?;
        if confirm.trim().eq_ignore_ascii_case("y") {
            let mut panel = PanelSetting::load_or_default(&self.data_dir);
            let def = PanelSetting::default();
            panel.listen = def.listen;
            panel.port = def.port;
            panel.base_path = def.base_path;
            panel.username = def.username;
            panel.password = def.password;
            panel.rotate_session_secret();
            panel.save(&self.data_dir)?;
            let _ = Command::new("systemctl").args(["restart", "sooya"]).status();
            println!("{}✅ 所有面板设置已重置为默认值，请使用默认端口 54321 访问。{}", GREEN, RESET);
        }
        self.pause()
    }

    async fn view_logs(&self) -> Result<()> {
        if let Ok(resp) = self
            .client
            .get(format!("{}/api/v1/logs", self.api_url))
            .header("x-sooya-token", self.auth_token())
            .send()
            .await
        {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(logs) = json.get("data").and_then(|d| d.as_str()) {
                    println!("\n{}", logs);
                    return self.pause();
                }
            }
        }
        if let Ok(out) = Command::new("journalctl").args(["-u", "sooya", "-n", "40", "--no-pager"]).output() {
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }
        self.pause()
    }

    fn set_autostart(&self, enable: bool) -> Result<()> {
        let action = if enable { "enable" } else { "disable" };
        match Command::new("systemctl").args([action, "sooya"]).status() {
            Ok(s) if s.success() => {
                if enable {
                    println!("{}✅ 设置 Sooya 开机自启成功{}", GREEN, RESET);
                } else {
                    println!("{}✅ 取消 Sooya 开机自启成功{}", GREEN, RESET);
                }
            }
            _ => println!("{}⚠️ 操作失败{}", RED, RESET),
        }
        self.pause()
    }

    fn prompt(&self, msg: &str) -> Result<String> {
        print!("{}", msg);
        io::stdout().flush()?;
        let mut buf = String::new();
        if io::stdin().read_line(&mut buf)? == 0 {
            return Err(ChainError::IoError(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")));
        }
        Ok(buf)
    }

    fn pause(&self) -> Result<()> {
        let _ = self.prompt("\n按回车键返回主菜单: ");
        Ok(())
    }
}
