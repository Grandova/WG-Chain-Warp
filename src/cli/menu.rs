use crate::error::{ChainError, Result};
use crate::health::diagnose::SystemDiagnostician;
use crate::model::config::{ChainProxyConfig, DnsConfig, RoutingConfig, VpnNodeConfig};
use crate::model::state::{ChainStatus, TestReport};
use crate::singbox::SingBoxManager;
use crate::wireguard::parser::parse_wireguard_ini;
use crate::wireguard::warp_register::WarpRegistrar;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

pub struct ConsoleMenu {
    api_url: String,
    data_dir: PathBuf,
    singbox_bin: String,
}

impl ConsoleMenu {
    pub fn new(api: &str, data_dir: PathBuf, singbox: &str) -> Self {
        let url = if api.starts_with("http://") || api.starts_with("https://") {
            api.to_string()
        } else {
            format!("http://{}", api)
        };

        Self {
            api_url: url,
            data_dir,
            singbox_bin: singbox.to_string(),
        }
    }

    fn config_path(&self) -> PathBuf {
        self.data_dir.join("config.json")
    }

    fn load_working_config(&self) -> ChainProxyConfig {
        let path = self.config_path();
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(cfg) = serde_json::from_str::<ChainProxyConfig>(&content) {
                    return cfg;
                }
            }
        }

        ChainProxyConfig {
            enabled: true,
            uplink_interface: None,
            vpn1: VpnNodeConfig {
                name: "VPN1 (入口)".to_string(),
                wireguard_config: String::new(),
            },
            vpn2: VpnNodeConfig {
                name: "Cloudflare WARP (出口)".to_string(),
                wireguard_config: String::new(),
            },
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
        }
    }

    fn save_working_config(&self, cfg: &ChainProxyConfig) -> Result<()> {
        let _ = fs::create_dir_all(&self.data_dir);
        let path = self.config_path();
        let json = serde_json::to_string_pretty(cfg)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        let stdin = io::stdin();
        let mut reader = stdin.lock();

        loop {
            self.print_header().await;

            print!("请选择操作编号 [0-12]: ");
            io::stdout().flush().unwrap();

            let mut choice = String::new();
            if reader.read_line(&mut choice).is_err() {
                break;
            }

            let choice = choice.trim();
            match choice {
                "1" => {
                    self.show_status().await;
                }
                "2" => {
                    self.configure_vpn1(&mut reader).await?;
                }
                "3" => {
                    self.configure_vpn2_manual(&mut reader).await?;
                }
                "4" => {
                    self.configure_vpn2_auto_warp().await?;
                }
                "5" => {
                    self.apply_configuration().await?;
                }
                "6" => {
                    self.run_test(&mut reader).await;
                }
                "7" | "c" | "C" | "cfg" => {
                    self.view_config(&mut reader).await?;
                }
                "8" => {
                    self.rollback().await;
                }
                "9" => {
                    self.stop_service().await;
                }
                "10" => {
                    self.diagnose();
                }
                "11" => {
                    self.view_logs().await;
                }
                "12" | "s" | "S" => {
                    self.restart_daemon().await;
                }
                "0" | "q" | "exit" => {
                    println!("\n已退出 chainproxy 管理菜单。");
                    break;
                }
                _ => {
                    println!("\n无效选项，请重新输入！");
                }
            }

            println!("\n按回车键继续...");
            let mut dummy = String::new();
            let _ = reader.read_line(&mut dummy);
        }

        Ok(())
    }

    async fn is_daemon_reachable(&self) -> bool {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(800))
            .build()
            .unwrap_or_default();
        let status_url = format!("{}/api/v1/status", self.api_url);
        client.get(&status_url).send().await.is_ok()
    }

    async fn ensure_daemon_running(&self) -> bool {
        if self.is_daemon_reachable().await {
            return true;
        }

        #[cfg(target_os = "linux")]
        {
            println!("💡 检测到后台守护进程未运行，正在尝试自动启动 (systemctl start chainproxy)...");
            let _ = std::process::Command::new("systemctl")
                .args(["start", "chainproxy"])
                .status();

            for _ in 0..5 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if self.is_daemon_reachable().await {
                    println!("✅ 后台守护服务启动就绪！");
                    return true;
                }
            }
        }

        false
    }

    async fn print_header(&self) {
        println!("\n==============================================================");
        println!("             chainproxy 链式 WireGuard 代理管理面板            ");
        println!("==============================================================");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(800))
            .build()
            .unwrap_or_default();
        let status_url = format!("{}/api/v1/status", self.api_url);
        let mut daemon_connected = false;

        if let Ok(resp) = client.get(&status_url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(data) = json.get("data") {
                    let state = data.get("state").and_then(|s| s.as_str()).unwrap_or("Unknown");
                    let visual = data.get("chain_visual").and_then(|v| v.as_str()).unwrap_or("");
                    let ver = data.get("active_config_version").and_then(|v| v.as_str()).unwrap_or("none");
                    println!(" 服务状态: {:<12} 活跃版本: {}", state, ver);
                    println!(" 链路拓扑: {}", visual);
                    println!("--------------------------------------------------------------");
                    daemon_connected = true;
                }
            }
        }

        if !daemon_connected {
            println!(" 提示: 后台服务未运行或连接中 (如需手动重启可执行: systemctl restart chainproxy)");
            println!("--------------------------------------------------------------");
        }

        println!("  1. 查看链路运行状态 (Status & Health)");
        println!("  2. 配置入口 WireGuard (第一层 VPN / 入口节点)");
        println!("  3. 配置出口 Cloudflare WARP (手动粘贴 INI)");
        println!("  4. 一键自动注册 WARP 并生成配置 (Auto Register WARP)");
        println!("  5. 事务式应用配置并启动 (Apply & Start)");
        println!("  6. 全链路连通性与分跳测试 (Test & Verify)");
        println!("  7. 查看节点配置详情 (View Node Configs)");
        println!("  8. 回滚至上一版本配置 (Rollback)");
        println!("  9. 停止服务并完全恢复网络 (Stop & Cleanup)");
        println!(" 10. 查看系统诊断报告 (Diagnose)");
        println!(" 11. 查看服务运行日志 (Logs)");
        println!(" 12. 重启后台守护服务 (Restart Daemon)");
        println!("  0. 退出管理菜单");
        println!("==============================================================");
    }

    async fn show_status(&self) {
        if !self.ensure_daemon_running().await {
            println!("\n❌ 无法连接守护进程 ({})", self.api_url);
            println!("提示: 请执行 'systemctl restart chainproxy' 并查看服务状态: 'systemctl status chainproxy'");
            return;
        }

        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/status", self.api_url);
        match client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(data) = json.get("data") {
                        if let Ok(status) = serde_json::from_value::<ChainStatus>(data.clone()) {
                            println!("\n==============================================================");
                            println!("                    CHAINPROXY 实时状态                       ");
                            println!("==============================================================");
                            println!(" 运行状态 : {:?}", status.state);
                            println!(" 活跃版本 : {}", status.active_config_version.unwrap_or_else(|| "none (未配置/未应用)".to_string()));
                            println!(" 运行时间 : {} 秒", status.uptime_seconds);
                            println!(" 链路拓扑 : {}", status.chain_visual);
                            println!("--------------------------------------------------------------");
                            let gw = status.physical.gateway.as_deref().unwrap_or("未检测到");
                            println!(" 物理网卡 : {} (网关: {}) [{}]", status.physical.interface, gw, status.physical.status);
                            println!(" VPN 1    : {} [{}]", if status.vpn1.name.is_empty() { "入口节点 (未配置)" } else { &status.vpn1.name }, status.vpn1.status);
                            println!(" VPN 2    : {} [{}]", if status.vpn2.name.is_empty() { "WARP 出口 (未配置)" } else { &status.vpn2.name }, status.vpn2.status);
                            let exit_info = if let Some(ref ip) = status.final_hop.exit_ip {
                                format!("{} (出口 IP: {})", status.final_hop.status, ip)
                            } else {
                                status.final_hop.status.clone()
                            };
                            println!(" 公网出口 : {}", exit_info);
                            println!("==============================================================");
                            return;
                        }
                    }
                    println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
                }
            }
            Err(e) => {
                println!("\n❌ 无法连接守护进程 ({}): {}", self.api_url, e);
                println!("提示: 请确认后台是否运行: systemctl status chainproxy");
            }
        }
    }

    async fn configure_vpn1<R: BufRead>(&self, reader: &mut R) -> Result<()> {
        println!("\n--- [配置入口 WireGuard (VPN1)] ---");
        println!("请直接粘贴 WireGuard 配置文本 (包含 [Interface] 与 [Peer])。");
        println!("输入完毕后，输入 EOF 或在单行输入 END 结束输入：\n");

        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            let trimmed = line.trim().to_string();
            if trimmed == "END" || trimmed == "EOF" {
                break;
            }
            lines.push(line);
            if trimmed.is_empty() && lines.len() > 5 {
                if lines.iter().any(|l| l.contains("[Peer]")) && lines.iter().any(|l| l.contains("Endpoint")) {
                    break;
                }
            }
        }

        let raw_conf = lines.join("");
        if raw_conf.trim().is_empty() {
            println!("输入为空，已取消。");
            return Ok(());
        }

        match parse_wireguard_ini(&raw_conf) {
            Ok(parsed) => {
                println!("\n✅ 入口 WireGuard 解析成功！");
                println!("- 本地地址 (Address): {:?}", parsed.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>());
                if !parsed.interface.dns.is_empty() {
                    println!("- DNS 服务器: {:?}", parsed.interface.dns);
                }
                if let Some(peer) = parsed.peers.first() {
                    println!("- 对端端点 (Endpoint): {:?}", peer.endpoint);
                    println!("- 对端公钥 (PublicKey): {}", peer.public_key);
                    println!("- 保活周期 (Keepalive): {:?}", peer.persistent_keepalive);
                }

                let mut cfg = self.load_working_config();
                cfg.vpn1.wireguard_config = raw_conf;
                self.save_working_config(&cfg)?;
                println!("💾 入口 WireGuard 配置已保存就绪！");
                println!("💡 提示: 链式代理需同时具备入口与出口节点，请继续按 [4] 自动注册 WARP (或按 [3] 粘贴出口)，最后按 [5] 启动生效。");
            }
            Err(e) => {
                println!("\n❌ 配置解析失败: {}", e);
            }
        }

        Ok(())
    }

    async fn configure_vpn2_manual<R: BufRead>(&self, reader: &mut R) -> Result<()> {
        println!("\n--- [配置出口 Cloudflare WARP (手动粘贴)] ---");
        println!("请粘贴 WARP WireGuard 配置文本，输入完毕后输入 END 或 EOF 结束：\n");

        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            let trimmed = line.trim().to_string();
            if trimmed == "END" || trimmed == "EOF" {
                break;
            }
            lines.push(line);
        }

        let raw_conf = lines.join("");
        if raw_conf.trim().is_empty() {
            println!("输入为空，已取消。");
            return Ok(());
        }

        match parse_wireguard_ini(&raw_conf) {
            Ok(parsed) => {
                println!("\n✅ 出口 WARP 配置解析成功！");
                println!("- 本地地址: {:?}", parsed.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>());
                if let Some(peer) = parsed.peers.first() {
                    println!("- WARP 端点: {:?}", peer.endpoint);
                }

                let mut cfg = self.load_working_config();
                cfg.vpn2.wireguard_config = raw_conf;
                self.save_working_config(&cfg)?;
                println!("💾 出口 WARP 配置已保存就绪！");
                println!("💡 提示: 请按 [5] 事务式应用配置并启动链路。");
            }
            Err(e) => {
                println!("\n❌ 配置解析失败: {}", e);
            }
        }

        Ok(())
    }

    async fn configure_vpn2_auto_warp(&self) -> Result<()> {
        println!("\n--- [一键自动注册 Cloudflare WARP] ---");
        println!("正在生成 Curve25519 密钥对并请求 Cloudflare 官方 API 注册设备...");

        match WarpRegistrar::register_warp().await {
            Ok(res) => {
                println!("\n🎉 Cloudflare WARP 自动注册成功！");
                println!("- 分配 IPv4 地址 : {}", res.address_v4);
                if let Some(ref v6) = res.address_v6 {
                    println!("- 分配 IPv6 地址 : {}", v6);
                }
                println!("- WARP 对端公钥  : {}", res.peer_public_key);
                println!("- WARP 默认端点  : {}", res.endpoint);

                let mut cfg = self.load_working_config();
                cfg.vpn2.wireguard_config = res.wireguard_config;
                self.save_working_config(&cfg)?;
                println!("💾 已成功将 WARP 绑定为链式出口！");
                println!("💡 提示: 入口与出口节点现已全部就绪！请按 [5] 应用配置并启动链路。");
            }
            Err(e) => {
                println!("\n❌ 自动注册失败: {}", e);
            }
        }

        Ok(())
    }

    async fn apply_configuration(&self) -> Result<()> {
        let cfg = self.load_working_config();
        println!("\n--- [事务式应用配置并启动] ---");

        if cfg.vpn1.wireguard_config.trim().is_empty() {
            println!("❌ 错误: 入口 WireGuard 未配置！请先执行选项 2。");
            return Ok(());
        }
        if cfg.vpn2.wireguard_config.trim().is_empty() {
            println!("❌ 错误: 出口 WARP 未配置！请执行选项 3 粘贴或选项 4 自动注册。");
            return Ok(());
        }

        if !self.ensure_daemon_running().await {
            println!("\n❌ 无法连接守护进程 ({})", self.api_url);
            println!("提示: 请执行 'systemctl restart chainproxy' 并查看状态: 'systemctl status chainproxy'");
            return Ok(());
        }

        // 检查本地/宿主机是否存在 sing-box 引擎，如缺失则尝试自动安装
        if SingBoxManager::resolve_binary(&self.singbox_bin).is_err() {
            println!("\n⚠️  [检测] 系统尚未安装 sing-box 代理引擎！");
            println!("正在自动为您拉取安装官方 sing-box 引擎 (curl -fsSL https://sing-box.app/install.sh | bash)...");
            let install_status = std::process::Command::new("sh")
                .arg("-c")
                .arg("curl -fsSL https://sing-box.app/install.sh | bash")
                .status();
            if install_status.map(|s| s.success()).unwrap_or(false) && SingBoxManager::resolve_binary(&self.singbox_bin).is_ok() {
                println!("✅ sing-box 自动安装成功！继续应用链路配置...\n");
            } else {
                println!("❌ 自动安装未能完成。请退出菜单在终端以 root 权限执行安装：");
                println!("   curl -fsSL https://sing-box.app/install.sh | sudo bash");
                println!("安装完成后重新进入面板按 [5] 即可启动链路。");
                return Ok(());
            }
        }

        println!("正在向后台发送事务 Apply 请求 (包含 30 秒看门狗与 SSH 零失联保护)...");
        let client = reqwest::Client::new();
        let apply_url = format!("{}/api/v1/config/apply", self.api_url);
        let payload = serde_json::json!({ "config": cfg });

        match client.post(&apply_url).json(&payload).send().await {
            Ok(resp) => {
                let json: serde_json::Value = resp.json().await.map_err(|e| ChainError::NetworkError(e.to_string()))?;
                if json.get("success").and_then(|s| s.as_bool()).unwrap_or(false) {
                    println!("\n🎉 配置已成功生效！链路服务已处于 Running 运行状态！");
                    if let Some(data) = json.get("data") {
                        if let Ok(report) = serde_json::from_value::<TestReport>(data.clone()) {
                            print_test_report(&report);
                        } else {
                            println!("{}", serde_json::to_string_pretty(data)?);
                        }
                    }
                } else {
                    println!("\n❌ 应用失败，已自动回滚: {}", json.get("error").and_then(|e| e.as_str()).unwrap_or("未知错误"));
                    println!("💡 宿主机网络与 SSH 连接已被系统看门狗与策略路由完整保护，未发生断网。");
                }
            }
            Err(e) => {
                println!("无法连接到守护进程: {}", e);
                println!("提示: 请确认后台是否已启动 'systemctl start chainproxy'");
            }
        }

        Ok(())
    }

    async fn run_test<R: BufRead>(&self, reader: &mut R) {
        if !self.ensure_daemon_running().await {
            println!("\n❌ 无法连接守护进程 ({})", self.api_url);
            println!("提示: 请执行 'systemctl restart chainproxy' 并查看状态: 'systemctl status chainproxy'");
            return;
        }

        // Check if service is currently running
        let status_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();
        let status_url = format!("{}/api/v1/status", self.api_url);

        let mut is_running = false;
        let mut active_version = None;
        if let Ok(resp) = status_client.get(&status_url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(data) = json.get("data") {
                    let state = data.get("state").and_then(|s| s.as_str()).unwrap_or("Unknown");
                    active_version = data.get("active_config_version").and_then(|v| v.as_str()).map(|s| s.to_string());
                    if state == "Running" {
                        is_running = true;
                    }
                }
            }
        }

        if !is_running || active_version.is_none() {
            println!("\n⚠️  [提示] 链式代理服务当前未处于运行状态 (尚未应用配置启动链路)！");
            println!("由于链路尚未启动，sing-box 本地链路探测端口尚未开启。");
            println!("\n💡 建议操作流程：");
            println!("  1. 按 [2] 导入入口 WireGuard 配置 (粘贴您的 WireGuard 节点)");
            println!("  2. 按 [4] 一键自动注册 Cloudflare WARP 出口 (或按 [3] 手动粘贴)");
            println!("  3. 按 [5] 事务式应用配置并启动 (Apply & Start)");
            println!("  4. 服务启动成功后，再按 [6] 进行全链路与出口 IP 探测验证！");
            print!("\n是否仍要向后台发送探测请求？(y/N): ");
            let _ = io::stdout().flush();
            let mut choice = String::new();
            if reader.read_line(&mut choice).is_err() {
                return;
            }
            if !choice.trim().eq_ignore_ascii_case("y") {
                return;
            }
        }

        println!("\n正在向后台请求全链路性能与分跳探测 (请稍候)...");
        let test_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(25))
            .build()
            .unwrap_or_default();
        let url = format!("{}/api/v1/config/test", self.api_url);
        match test_client.post(&url).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(data) = json.get("data") {
                        if let Ok(report) = serde_json::from_value::<TestReport>(data.clone()) {
                            print_test_report(&report);
                            return;
                        }
                    }
                    println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
                }
            }
            Err(e) => {
                println!("请求失败: {}", e);
            }
        }
    }

    async fn view_config<R: BufRead>(&self, reader: &mut R) -> Result<()> {
        println!("\n==============================================================");
        println!("                chainproxy 节点配置查看与详情                ");
        println!("==============================================================");

        let working_cfg = self.load_working_config();

        // 尝试从后台获取在线活跃配置
        let mut active_version: Option<String> = None;
        let mut daemon_state: Option<String> = None;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(800))
            .build()
            .unwrap_or_default();
        let config_url = format!("{}/api/v1/config", self.api_url);

        if let Ok(resp) = client.get(&config_url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(data) = json.get("data") {
                    daemon_state = data.get("status").and_then(|s| s.as_str()).map(|s| s.to_string());
                    active_version = data.get("active_version").and_then(|v| v.as_str()).map(|s| s.to_string());
                }
            }
        }

        println!(" [配置生效状态概览]");
        let state_str = daemon_state.unwrap_or_else(|| "守护进程未运行".to_string());
        let ver_str = active_version.unwrap_or_else(|| "none (尚未应用生效)".to_string());
        println!("   • 服务运行状态 : {}", state_str);
        println!("   • 当前生效版本 : {}", ver_str);
        println!("   • 本地配置存储 : /var/lib/chainproxy/config.json");
        println!("--------------------------------------------------------------");

        // 显示入口 VPN 1
        println!(" 【第一层: 入口 WireGuard 节点 (VPN 1)】");
        if working_cfg.vpn1.wireguard_config.trim().is_empty() {
            println!("   • 状态     : ❌ 未配置 (请按 2 粘贴导入)");
        } else {
            match parse_wireguard_ini(&working_cfg.vpn1.wireguard_config) {
                Ok(parsed) => {
                    println!("   • 状态     : ✅ 已保存就绪");
                    println!("   • 节点名称 : {}", working_cfg.vpn1.name);
                    println!("   • 本地地址 : {:?}", parsed.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>());
                    if !parsed.interface.dns.is_empty() {
                        println!("   • DNS 服务器: {:?}", parsed.interface.dns);
                    }
                    if let Some(peer) = parsed.peers.first() {
                        if let Some(ref ep) = peer.endpoint {
                            println!("   • 对端端点 : {}:{}", ep.host, ep.port);
                        }
                        println!("   • 对端公钥 : {}", peer.public_key);
                        println!("   • 允许 IP  : {:?}", peer.allowed_ips.iter().map(|a| a.to_string()).collect::<Vec<_>>());
                        if let Some(keepalive) = peer.persistent_keepalive {
                            println!("   • 保活周期 : {} 秒", keepalive);
                        }
                    }
                }
                Err(e) => {
                    println!("   • 状态     : ⚠️  配置文本解析异常: {}", e);
                }
            }
        }

        // 显示出口 WARP
        println!("\n 【第二层: 出口 Cloudflare WARP 节点 (VPN 2)】");
        if working_cfg.vpn2.wireguard_config.trim().is_empty() {
            println!("   • 状态     : ❌ 未配置 (请按 4 一键自动注册或按 3 手动粘贴)");
        } else {
            match parse_wireguard_ini(&working_cfg.vpn2.wireguard_config) {
                Ok(parsed) => {
                    println!("   • 状态     : ✅ 已保存就绪");
                    println!("   • 节点名称 : {}", working_cfg.vpn2.name);
                    println!("   • 本地地址 : {:?}", parsed.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>());
                    if let Some(peer) = parsed.peers.first() {
                        if let Some(ref ep) = peer.endpoint {
                            println!("   • WARP端点 : {}:{}", ep.host, ep.port);
                        }
                        println!("   • WARP公钥 : {}", peer.public_key);
                        println!("   • 允许 IP  : {:?}", peer.allowed_ips.iter().map(|a| a.to_string()).collect::<Vec<_>>());
                        if let Some(keepalive) = peer.persistent_keepalive {
                            println!("   • 保活周期 : {} 秒", keepalive);
                        }
                    }
                }
                Err(e) => {
                    println!("   • 状态     : ⚠️  配置文本解析异常: {}", e);
                }
            }
        }

        // 高级策略
        println!("\n 【底层网络与安全策略】");
        println!("   • SSH 零失联防护 : {}", if working_cfg.routing.preserve_inbound_connections { "已启用 (conntrack mark 0x88 保证会话畅通)" } else { "未启用" });
        println!("   • 嵌套 Detour 模式 : 强制 WARP 流量通过 VPN1 隧道");
        println!("==============================================================");

        print!("\n是否查看完整 WireGuard 原始配置？(1: 入口VPN1, 2: 出口WARP, 回车返回): ");
        let _ = io::stdout().flush();
        let mut input = String::new();
        if reader.read_line(&mut input).is_ok() {
            let choice = input.trim();
            if choice == "1" {
                println!("\n--- [入口 WireGuard (VPN1) 原始配置] ---");
                if working_cfg.vpn1.wireguard_config.trim().is_empty() {
                    println!("(尚未配置任何入口信息)");
                } else {
                    println!("{}", working_cfg.vpn1.wireguard_config.trim());
                }
            } else if choice == "2" {
                println!("\n--- [出口 Cloudflare WARP 原始配置] ---");
                if working_cfg.vpn2.wireguard_config.trim().is_empty() {
                    println!("(尚未配置任何 WARP 出口信息)");
                } else {
                    println!("{}", working_cfg.vpn2.wireguard_config.trim());
                }
            }
        }

        Ok(())
    }

    async fn rollback(&self) {
        if !self.ensure_daemon_running().await {
            println!("\n❌ 无法连接守护进程 ({})", self.api_url);
            println!("提示: 请执行 'systemctl restart chainproxy' 并查看状态: 'systemctl status chainproxy'");
            return;
        }

        println!("\n正在请求回滚至上一版本配置...");
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/rollback", self.api_url);
        match client.post(&url).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
                }
            }
            Err(e) => {
                println!("回滚请求失败: {}", e);
            }
        }
    }

    async fn stop_service(&self) {
        if !self.ensure_daemon_running().await {
            println!("\n❌ 无法连接守护进程 ({})", self.api_url);
            println!("提示: 请执行 'systemctl restart chainproxy' 并查看状态: 'systemctl status chainproxy'");
            return;
        }

        println!("\n正在请求安全停止链式代理并恢复系统网络...");
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/stop", self.api_url);
        match client.post(&url).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
                }
            }
            Err(e) => {
                println!("停止请求失败: {}", e);
            }
        }
    }

    fn diagnose(&self) {
        println!("\n正在采集系统脱敏诊断数据...\n");
        let report = SystemDiagnostician::generate_report(&self.singbox_bin);
        println!("{}", report);
    }

    async fn view_logs(&self) {
        if !self.ensure_daemon_running().await {
            println!("\n❌ 无法连接守护进程 ({})", self.api_url);
            println!("提示: 请执行 'systemctl restart chainproxy' 并查看状态: 'systemctl status chainproxy'");
            return;
        }

        println!("\n正在获取最近运行日志 (最新 30 行)...");
        println!("--------------------------------------------------------------");
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/logs", self.api_url);
        match client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(logs) = json.get("data").and_then(|d| d.as_str()) {
                        if logs.trim().is_empty() {
                            println!("(暂无日志记录)");
                        } else {
                            println!("{}", logs.trim());
                        }
                        println!("--------------------------------------------------------------");
                        println!("💡 提示: 若需持续跟踪实时日志，可在终端执行: journalctl -u chainproxy -f");
                        return;
                    }
                    println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
                }
            }
            Err(e) => {
                println!("获取日志失败: {}", e);
            }
        }
    }

    async fn restart_daemon(&self) {
        println!("\n正在重启后台守护服务...");
        #[cfg(target_os = "linux")]
        {
            let status = std::process::Command::new("systemctl")
                .args(["restart", "chainproxy"])
                .status();
            match status {
                Ok(s) if s.success() => {
                    println!("✅ 服务重启命令已发出，正在等待后台就绪...");
                    for _ in 0..6 {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        if self.is_daemon_reachable().await {
                            println!("🎉 守护进程连接正常！");
                            return;
                        }
                    }
                    println!("⚠️ 后台服务已重启，但 API 响应略有延迟，请稍后按 1 刷新状态。");
                }
                _ => {
                    eprintln!("❌ 执行 systemctl restart chainproxy 失败，请检查是否具备 root 权限。");
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            println!("当前操作系统非 Linux，请在终端手动运行: chainproxy daemon");
        }
    }
}

fn print_test_report(report: &TestReport) {
    println!("\n==============================================================");
    println!("                全链路连通性与分跳探测报告                    ");
    println!("==============================================================");
    if report.success {
        println!(" 总体探测结论: ✅ 链路全线畅通，链式代理正常运行！");
    } else {
        println!(" 总体探测结论: ⚠️  链路探测未完全通过 (可能尚未启动或节点不可达)");
    }
    println!("--------------------------------------------------------------");

    println!(" [1] 物理底层网络 (VPS 宿主机)");
    println!("     • 接口网卡 : {}", report.physical.name);
    println!("     • 默认网关 : {}", if report.physical.endpoint.is_empty() { "未检测到" } else { &report.physical.endpoint });
    println!("     • 连通状态 : {}", if report.physical.reachable { "✅ 正常 (UP)" } else { "❌ 异常" });

    println!("\n [2] 第一跳: 入口 WireGuard 节点");
    println!("     • 节点名称 : {}", if report.vpn1.name.is_empty() { "VPN 1" } else { &report.vpn1.name });
    println!("     • 对端端点 : {}", if report.vpn1.endpoint.is_empty() { "未配置" } else { &report.vpn1.endpoint });
    println!("     • 隧道连通 : {}", if report.vpn1.reachable { "✅ 正常连接" } else { "❌ 连接失败" });
    if let Some(lat) = report.vpn1.latency_ms {
        println!("     • 节点延迟 : {} ms", lat);
    }
    if let Some(ref msg) = report.vpn1.message {
        println!("     • 探测详情 : {}", msg);
    }

    println!("\n [3] 第二跳: Cloudflare WARP 出口 (经第一跳隧道二次封装)");
    println!("     • 节点名称 : {}", if report.vpn2.name.is_empty() { "Cloudflare WARP" } else { &report.vpn2.name });
    println!("     • 对端端点 : {}", if report.vpn2.endpoint.is_empty() { "未配置" } else { &report.vpn2.endpoint });
    println!("     • 隧道连通 : {}", if report.vpn2.reachable { "✅ 正常连接" } else { "❌ 连接失败" });
    if let Some(lat) = report.vpn2.latency_ms {
        println!("     • 节点延迟 : {} ms", lat);
    }
    println!("     • WARP状态 : {}", report.vpn2.status);

    println!("\n [4] 最终公网出口 (Internet Egress)");
    println!("     • 外网访问 : {}", if report.final_exit.internet_ok { "✅ 正常畅通" } else { "❌ 无法访问公网" });
    if let Some(ref ip) = report.final_exit.exit_ip {
        println!("     • 最终公网 IP : {}", ip);
    }
    if let Some(ref country) = report.final_exit.exit_country {
        println!("     • 出口归属地区: {}", country);
    }
    if let Some(ref isp) = report.final_exit.exit_isp {
        println!("     • 出口运营商  : {}", isp);
    }
    if let Some(lat) = report.final_exit.latency_ms {
        println!("     • 全链路总延迟: {} ms", lat);
    }
    println!("==============================================================");

    if !report.success {
        println!("💡 排查建议:");
        println!("  - 若服务状态为 Stopped，请先按 [2] 导入 WireGuard、按 [4] 注册 WARP、按 [5] 应用启动");
        println!("  - 若已启动但 VPN1 失败，请检查入口节点的 Endpoint、公私钥与 AllowedIPs 是否有效");
        println!("  - 可按 [10] 查看最新日志以了解后台详细握手情况");
    }
}
