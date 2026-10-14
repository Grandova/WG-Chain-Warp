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
    _singbox_bin: String,
    client: reqwest::Client,
}

impl ConsoleMenu {
    pub fn new(api_url: &str, data_dir: PathBuf, singbox_bin: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            api_url: api_url.to_string(),
            data_dir,
            _singbox_bin: singbox_bin.to_string(),
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

            let choice = self.prompt("\n请输入选项编号 [0-11]: ")?;
            match choice.trim() {
                "1" => self.start_panel_service().await?,
                "2" => self.stop_panel_service().await?,
                "3" => self.restart_panel_service().await?,
                "4" => self.show_detailed_status(daemon_status.as_ref()).await?,
                "5" => self.change_credentials().await?,
                "6" => self.change_port_and_path().await?,
                "7" => self.show_panel_access_info(&panel, &host_ip)?,
                "8" => self.reset_panel_settings().await?,
                "9" => self.view_logs().await?,
                "10" => self.set_autostart(true)?,
                "11" => self.set_autostart(false)?,
                "0" | "q" | "exit" => {
                    println!("已退出 chainproxy 面板管理脚本。");
                    break;
                }
                _ => {
                    println!("{}无效选项，请输入 0-11 之间的数字。{}", YELLOW, RESET);
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
        println!("\n{}{}=================================================================={}", BOLD, CYAN, RESET);
        println!("{}{}             chainproxy Web 面板管理脚本 (x-ui 架构)              {}", BOLD, CYAN, RESET);
        println!("{}{}=================================================================={}", BOLD, CYAN, RESET);

        match status {
            Some(st) => {
                let proxy_badge = match st.state {
                    ServiceState::Running => format!("{}运行中 (Running){}", GREEN, RESET),
                    ServiceState::Failed => format!("{}异常 (Failed){}", RED, RESET),
                    _ => format!("{}未启动 (Stopped){}", YELLOW, RESET),
                };
                println!(
                    " 面板守护进程 : {}运行中 (Active){}  | 代理引擎: {}",
                    GREEN, RESET, proxy_badge
                );
                println!(" 当前链路拓扑 : {}", st.chain_visual);
            }
            None => {
                println!(
                    " 面板守护进程 : {}未运行 (Stopped){} (可执行选项 1 启动面板)",
                    RED, RESET
                );
            }
        }

        let display_ip = if panel.listen == "0.0.0.0" || panel.listen == "::" || panel.listen.is_empty() {
            host_ip
        } else {
            panel.listen.as_str()
        };
        println!(
            " Web 控制台   : {}{}http://{}:{}{}{}",
            BOLD, GREEN, display_ip, panel.port, panel.base_path, RESET
        );
        println!(
            " 登录用户名   : {}{}{} (所有 WireGuard / WARP / 节点配置均在网页端完成)",
            CYAN, panel.username, RESET
        );
        println!("{}{}------------------------------------------------------------------{}", BOLD, CYAN, RESET);
    }

    fn print_menu_options(&self) {
        println!("  {}1.{} 启动面板服务 (Start Panel)", GREEN, RESET);
        println!("  {}2.{} 停止面板与代理并恢复原网络 (Stop Panel & Proxy)", GREEN, RESET);
        println!("  {}3.{} 重启面板服务 (Restart Panel)", GREEN, RESET);
        println!("  {}4.{} 查看面板与链路运行状态 (Status)", GREEN, RESET);
        println!(" -----------------------------------------------------------------");
        println!("  {}5.{} 重置/修改面板登录用户名与密码 (Reset Username & Password)", CYAN, RESET);
        println!("  {}6.{} 修改面板监听端口与 URL 根路径 (Change Port & Base Path)", CYAN, RESET);
        println!("  {}7.{} 查看当前面板访问地址与账号信息 (Show Panel Info)", CYAN, RESET);
        println!("  {}8.{} 恢复面板出厂默认设置 (Reset Panel Settings)", CYAN, RESET);
        println!(" -----------------------------------------------------------------");
        println!("  {}9.{} 查看面板与引擎实时日志 (View Logs)", YELLOW, RESET);
        println!(" {}10.{} 设置面板开机自启 (Enable Autostart)", YELLOW, RESET);
        println!(" {}11.{} 取消面板开机自启 (Disable Autostart)", YELLOW, RESET);
        println!(" -----------------------------------------------------------------");
        println!("  {}0.{} 退出管理脚本 (Exit)", RED, RESET);
    }

    async fn fetch_status(&self) -> Option<ChainStatus> {
        let url = format!("{}/api/v1/status", self.api_url);
        let resp = self.client.get(&url).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let data = json.get("data")?.clone();
        serde_json::from_value(data).ok()
    }

    async fn start_panel_service(&self) -> Result<()> {
        println!("\n正在启动 chainproxy 面板服务...");
        let status = Command::new("systemctl")
            .args(["start", "chainproxy"])
            .status();
        match status {
            Ok(s) if s.success() => {
                tokio::time::sleep(Duration::from_millis(800)).await;
                println!("{}✅ chainproxy 面板服务已启动！{}", GREEN, RESET);
            }
            _ => {
                println!("{}⚠️ 未能通过 systemctl 启动，请检查 systemd 服务配置。{}", YELLOW, RESET);
            }
        }
        self.pause()
    }

    async fn stop_panel_service(&self) -> Result<()> {
        println!("\n正在停止代理链路并恢复宿主机原始网络...");
        let stop_url = format!("{}/api/v1/stop", self.api_url);
        let _ = self.client.post(&stop_url).send().await;

        println!("正在停止 chainproxy 守护服务...");
        let _ = Command::new("systemctl")
            .args(["stop", "chainproxy"])
            .status();
        println!("{}✅ 服务已停止，原始网络已恢复。{}", GREEN, RESET);
        self.pause()
    }

    async fn restart_panel_service(&self) -> Result<()> {
        println!("\n正在重启 chainproxy 面板服务...");
        let status = Command::new("systemctl")
            .args(["restart", "chainproxy"])
            .status();
        match status {
            Ok(s) if s.success() => {
                tokio::time::sleep(Duration::from_millis(800)).await;
                println!("{}✅ chainproxy 面板服务已重启！{}", GREEN, RESET);
            }
            _ => {
                println!("{}⚠️ 重启命令返回非零状态，请使用选项 9 查看运行日志。{}", YELLOW, RESET);
            }
        }
        self.pause()
    }

    async fn show_detailed_status(&self, status: Option<&ChainStatus>) -> Result<()> {
        println!("\n--- [面板与服务运行状态] ---");
        if let Some(st) = status {
            println!("代理引擎状态 : {:?}", st.state);
            println!("持续运行时间 : {} 秒", st.uptime_seconds);
            println!("当前生效版本 : {}", st.active_config_version.as_deref().unwrap_or("无"));
            println!("当前链路拓扑 : {}", st.chain_visual);
            println!("物理出口网卡 : {} (网关: {:?}) [{}]", st.physical.interface, st.physical.gateway, st.physical.status);
            println!("第一跳节点   : {} ({}) [{}]", st.vpn1.name, st.vpn1.endpoint, st.vpn1.status);
            println!("第二跳节点   : {} ({}) [{}]", st.vpn2.name, st.vpn2.endpoint, st.vpn2.status);
        } else {
            println!("{}守护进程当前未响应。{}", YELLOW, RESET);
        }
        println!("\n--- [systemd 服务状态摘要] ---");
        if let Ok(out) = Command::new("systemctl")
            .args(["status", "chainproxy", "--no-pager", "-n", "10"])
            .output()
        {
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }
        self.pause()
    }

    async fn change_credentials(&self) -> Result<()> {
        println!("\n--- [修改 Web 面板登录用户名与密码] ---");
        let mut panel = PanelSetting::load_or_default(&self.data_dir);
        let new_user = self.prompt(&format!("请输入新用户名 [当前: {}]: ", panel.username))?;
        let new_pass = self.prompt("请输入新登录密码: ")?;

        if !new_user.trim().is_empty() {
            panel.username = new_user.trim().to_string();
        }
        if !new_pass.trim().is_empty() {
            panel.password = new_pass.trim().to_string();
        } else {
            println!("{}❌ 密码未输入，已取消修改。{}", RED, RESET);
            return self.pause();
        }

        panel.rotate_session_secret();
        panel.save(&self.data_dir)?;
        let _ = Command::new("systemctl").args(["restart", "chainproxy"]).status();
        tokio::time::sleep(Duration::from_millis(600)).await;
        println!(
            "{}✅ 面板登录凭证已更新并生效！新用户名: {}{}",
            GREEN, panel.username, RESET
        );
        self.pause()
    }

    async fn change_port_and_path(&self) -> Result<()> {
        println!("\n--- [修改 Web 面板监听端口与根路径] ---");
        let mut panel = PanelSetting::load_or_default(&self.data_dir);

        let port_str = self.prompt(&format!("请输入新面板端口 (1-65535) [当前: {}]: ", panel.port))?;
        if !port_str.trim().is_empty() {
            match port_str.trim().parse::<u16>() {
                Ok(p) if p > 0 => panel.port = p,
                _ => {
                    println!("{}❌ 端口格式无效，必须在 1 ~ 65535 之间。{}", RED, RESET);
                    return self.pause();
                }
            }
        }

        let bp_str = self.prompt(&format!("请输入面板 URL 根路径 [当前: {}]: ", panel.base_path))?;
        if !bp_str.trim().is_empty() {
            panel.base_path = bp_str.trim().to_string();
        }

        panel.normalize();
        panel.save(&self.data_dir)?;
        let _ = Command::new("systemctl").args(["restart", "chainproxy"]).status();
        tokio::time::sleep(Duration::from_millis(600)).await;
        let host_ip = Self::detect_server_ip();
        println!(
            "{}✅ 面板端口与路径已更新并重启生效！新访问地址: http://{}:{}{}{}",
            GREEN, host_ip, panel.port, panel.base_path, RESET
        );
        self.pause()
    }

    fn show_panel_access_info(&self, panel: &PanelSetting, host_ip: &str) -> Result<()> {
        println!("\n================ Web 面板访问与账号信息 ================");
        println!(" 面板访问地址 : {}http://{}:{}{}{}", GREEN, host_ip, panel.port, panel.base_path, RESET);
        println!(" 面板监听地址 : {}:{}", panel.listen, panel.port);
        println!(" 面板根路径   : {}", panel.base_path);
        println!(" 登录用户名   : {}", panel.username);
        println!(" 登录密  码   : {}", panel.password);
        println!("========================================================");
        self.pause()
    }

    async fn reset_panel_settings(&self) -> Result<()> {
        let confirm = self.prompt("\n确认将面板端口重置为 54321、账密重置为 admin/admin 吗？(y/N): ")?;
        if confirm.trim().eq_ignore_ascii_case("y") {
            let mut panel = PanelSetting::default();
            panel.save(&self.data_dir)?;
            let _ = Command::new("systemctl").args(["restart", "chainproxy"]).status();
            tokio::time::sleep(Duration::from_millis(600)).await;
            println!("{}✅ 已恢复面板默认设置 (端口: 54321, 用户名: admin, 密码: admin)。{}", GREEN, RESET);
        } else {
            println!("已取消重置。");
        }
        self.pause()
    }

    async fn view_logs(&self) -> Result<()> {
        println!("\n--- [面板与 sing-box 最近运行日志] ---");
        let url = format!("{}/api/v1/logs", self.api_url);
        if let Ok(resp) = self.client.get(&url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(logs) = json.get("data").and_then(|d| d.as_str()) {
                    println!("{}", logs);
                    return self.pause();
                }
            }
        }
        if let Ok(out) = Command::new("journalctl")
            .args(["-u", "chainproxy", "-n", "40", "--no-pager"])
            .output()
        {
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }
        self.pause()
    }

    fn set_autostart(&self, enable: bool) -> Result<()> {
        let action = if enable { "enable" } else { "disable" };
        let status = Command::new("systemctl")
            .args([action, "chainproxy"])
            .status();
        match status {
            Ok(s) if s.success() => {
                if enable {
                    println!("{}✅ 已设置 chainproxy 开机自启。{}", GREEN, RESET);
                } else {
                    println!("{}✅ 已取消 chainproxy 开机自启。{}", GREEN, RESET);
                }
            }
            _ => {
                println!("{}⚠️ 执行 systemctl {} 失败。{}", YELLOW, action, RESET);
            }
        }
        self.pause()
    }

    fn prompt(&self, msg: &str) -> Result<String> {
        print!("{}", msg);
        io::stdout().flush()?;
        let mut buf = String::new();
        let n = io::stdin().read_line(&mut buf)?;
        if n == 0 {
            return Err(ChainError::IoError(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF",
            )));
        }
        Ok(buf)
    }

    fn pause(&self) -> Result<()> {
        let _ = self.prompt("\n按回车键返回管理主菜单...");
        Ok(())
    }
}
