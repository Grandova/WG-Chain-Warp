use crate::error::{ChainError, Result};
use crate::health::diagnose::SystemDiagnostician;
use crate::model::config::{ChainProxyConfig, DnsConfig, ProxyMode, RoutingConfig, VpnNodeConfig};
use crate::model::state::{ChainStatus, TestReport};
use crate::proxy::socks5::Socks5Config;
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
            mode: ProxyMode::default(),
            uplink_interface: None,
            vpn1: VpnNodeConfig {
                name: "VPN1 (入口)".to_string(),
                wireguard_config: String::new(),
            },
            vpn2: VpnNodeConfig {
                name: "Cloudflare WARP (出口)".to_string(),
                wireguard_config: String::new(),
            },
            socks5: None,
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

            print!("请选择操作编号 [0-14]: ");
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
                "2" | "m" | "M" => {
                    self.switch_proxy_mode(&mut reader).await?;
                }
                "3" => {
                    self.configure_vpn1(&mut reader).await?;
                }
                "4" | "s5" | "S5" => {
                    self.configure_socks5(&mut reader).await?;
                }
                "5" => {
                    self.configure_vpn2_manual(&mut reader).await?;
                }
                "6" => {
                    self.configure_vpn2_auto_warp().await?;
                }
                "7" | "apply" => {
                    self.apply_configuration().await?;
                }
                "8" | "test" => {
                    self.run_test(&mut reader).await;
                }
                "9" | "c" | "C" | "cfg" => {
                    self.view_config(&mut reader).await?;
                }
                "10" | "rb" => {
                    self.rollback().await;
                }
                "11" | "stop" => {
                    self.stop_service().await;
                }
                "12" | "diag" => {
                    self.diagnose();
                }
                "13" | "log" | "logs" => {
                    self.view_logs().await;
                }
                "14" | "s" | "S" => {
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

        let working_cfg = self.load_working_config();
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
                    println!(" 运行模式: {}", working_cfg.mode.description());
                    println!("--------------------------------------------------------------");
                    daemon_connected = true;
                }
            }
        }

        if !daemon_connected {
            println!(" 运行模式: {}", working_cfg.mode.description());
            println!(" 提示: 后台服务未运行或连接中 (如需手动重启可执行: systemctl restart chainproxy)");
            println!("--------------------------------------------------------------");
        }

        println!("  1. 查看链路运行状态 (Status & Health)");
        println!("  2. 切换代理运行模式 (Switch Mode) [当前: {}]", working_cfg.mode.description());
        println!("  3. 配置入口 WireGuard (VPN1 / WG 节点)");
        println!("  4. 配置入口 Socks5 代理 (Socks5 节点 / 中继)");
        println!("  5. 配置出口 Cloudflare WARP (手动粘贴 INI)");
        println!("  6. 一键自动注册 WARP 并生成配置 (Auto Register WARP)");
        println!("  7. 事务式应用配置并启动 (Apply & Start)");
        println!("  8. 全链路连通性与分跳测试 (Test & Verify)");
        println!("  9. 查看节点配置详情 (View Node Configs)");
        println!(" 10. 回滚至上一版本配置 (Rollback)");
        println!(" 11. 停止服务并完全恢复网络 (Stop & Cleanup)");
        println!(" 12. 查看系统诊断报告 (Diagnose)");
        println!(" 13. 查看服务运行日志 (Logs)");
        println!(" 14. 重启后台守护服务 (Restart Daemon)");
        println!("  0. 退出管理菜单");
        println!("==============================================================");
    }

    async fn show_status(&self) {
        if !self.ensure_daemon_running().await {
            println!("\n❌ 无法连接守护进程 ({})", self.api_url);
            println!("提示: 请执行 'systemctl restart chainproxy' 并查看服务状态: 'systemctl status chainproxy'");
            return;
        }

        let working_cfg = self.load_working_config();
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
                            println!(" 运行模式 : {}", working_cfg.mode.description());
                            println!(" 运行时间 : {} 秒", status.uptime_seconds);
                            println!(" 链路拓扑 : {}", status.chain_visual);
                            println!("--------------------------------------------------------------");
                            let gw = status.physical.gateway.as_deref().unwrap_or("未检测到");
                            println!(" 物理网卡 : {} (网关: {}) [{}]", status.physical.interface, gw, status.physical.status);
                            println!(" 节点 1   : {} [{}]", if status.vpn1.name.is_empty() { "未配置" } else { &status.vpn1.name }, status.vpn1.status);
                            println!(" 节点 2   : {} [{}]", if status.vpn2.name.is_empty() { "未配置" } else { &status.vpn2.name }, status.vpn2.status);
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

    async fn switch_proxy_mode<R: BufRead>(&self, reader: &mut R) -> Result<()> {
        let mut cfg = self.load_working_config();
        println!("\n==============================================================");
        println!("                    切换代理运行模式                          ");
        println!("==============================================================");
        println!(" 当前运行模式: {}", cfg.mode.description());
        println!(" 可选模式列表:");
        println!("   1. WireGuard -> WARP 双层链式代理 (默认模式: WG 前置隧道 + WARP 出口)");
        println!("   2. Socks5 -> WARP 链式代理 (Socks5 前置中继 + WARP 出口)");
        println!("   3. WireGuard 单独出站 (直连 WG 出口，不经过 WARP)");
        println!("   4. Socks5 单独出站 (直连 Socks5 出口，不经过 WARP)");
        println!("   5. WARP 单独出站 (直连 Cloudflare WARP 出口)");
        println!("--------------------------------------------------------------");
        print!("请选择目标模式编号 [1-5] (回车保持当前): ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        if reader.read_line(&mut input).is_ok() {
            let choice = input.trim();
            let new_mode = match choice {
                "1" => Some(ProxyMode::WgChainWarp),
                "2" => Some(ProxyMode::SocksChainWarp),
                "3" => Some(ProxyMode::StandaloneWg),
                "4" => Some(ProxyMode::StandaloneSocks),
                "5" => Some(ProxyMode::StandaloneWarp),
                "" => None,
                _ => {
                    println!("无效选择，保持当前模式不变。");
                    None
                }
            };

            if let Some(mode) = new_mode {
                cfg.mode = mode;
                self.save_working_config(&cfg)?;
                println!("\n🎉 运行模式已成功切换为: {}", cfg.mode.description());

                match cfg.mode {
                    ProxyMode::SocksChainWarp | ProxyMode::StandaloneSocks => {
                        if cfg.socks5.is_none() {
                            println!("💡 提示: 检测到尚未配置 Socks5 节点，请按 [4] 输入 Socks5 代理信息。");
                        }
                    }
                    ProxyMode::WgChainWarp | ProxyMode::StandaloneWg => {
                        if cfg.vpn1.wireguard_config.trim().is_empty() {
                            println!("💡 提示: 检测到尚未配置 WireGuard 入口，请按 [3] 粘贴 WireGuard 节点。");
                        }
                    }
                    ProxyMode::StandaloneWarp => {
                        if cfg.vpn2.wireguard_config.trim().is_empty() {
                            println!("💡 提示: 检测到尚未配置 WARP 出口，请按 [6] 自动注册或按 [5] 粘贴配置。");
                        }
                    }
                }
                println!("💡 提示: 模式变更后，请按 [7] 应用并启动生效。");
            }
        }

        Ok(())
    }

    async fn configure_socks5<R: BufRead>(&self, reader: &mut R) -> Result<()> {
        println!("\n==============================================================");
        println!("                  配置入口 Socks5 代理节点                    ");
        println!("==============================================================");
        println!(" 支持多种标准与厂商格式智能自动解析 (密码含特殊字符亦可完美识别)：");
        println!("   • user:password@host:port (例如: user:pass@1.2.3.4:1080)");
        println!("   • socks5://user:password@host:port");
        println!("   • host:port:user:password");
        println!("   • host:port (无密码认证)");
        println!("--------------------------------------------------------------");
        print!("请输入 Socks5 代理字符串 (回车取消): ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        if reader.read_line(&mut input).is_err() {
            return Ok(());
        }

        let raw = input.trim();
        if raw.is_empty() {
            println!("输入为空，已取消。");
            return Ok(());
        }

        match Socks5Config::parse(raw) {
            Ok(s5) => {
                println!("\n✅ Socks5 代理连接信息解析成功！");
                println!("   • 代理服务器 : {}", s5.server);
                println!("   • 服务端口   : {}", s5.port);
                if let Some(ref u) = s5.username {
                    println!("   • 认证用户   : {}", u);
                }
                if s5.password.is_some() {
                    println!("   • 认证密码   : ******** (已安全掩码保护)");
                }
                println!("   • 安全连接串 : {}", s5.redacted_string());

                let mut cfg = self.load_working_config();
                cfg.socks5 = Some(s5);

                if cfg.mode == ProxyMode::WgChainWarp || cfg.mode == ProxyMode::StandaloneWg {
                    print!("\n是否同时将当前运行模式切换为 [2] Socks5 -> WARP 链式代理？(Y/n): ");
                    let _ = io::stdout().flush();
                    let mut m_choice = String::new();
                    let _ = reader.read_line(&mut m_choice);
                    if !m_choice.trim().eq_ignore_ascii_case("n") {
                        cfg.mode = ProxyMode::SocksChainWarp;
                        println!("🎉 运行模式已自动切换为: {}", cfg.mode.description());
                    }
                }

                self.save_working_config(&cfg)?;
                println!("💾 Socks5 代理配置已保存就绪！");
                println!("💡 提示: 请按 [7] 事务式应用配置并启动链路生效。");
            }
            Err(e) => {
                println!("\n❌ Socks5 格式解析失败: {}", e);
            }
        }

        Ok(())
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
        println!("当前生效模式: {}", cfg.mode.description());

        match cfg.mode {
            ProxyMode::WgChainWarp => {
                if cfg.vpn1.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: 入口 WireGuard 未配置！请先执行选项 3 导入 WireGuard。");
                    return Ok(());
                }
                if cfg.vpn2.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: 出口 WARP 未配置！请先执行选项 6 自动注册或选项 5 粘贴 WARP。");
                    return Ok(());
                }
            }
            ProxyMode::SocksChainWarp => {
                if cfg.socks5.is_none() {
                    println!("❌ 错误: 入口 Socks5 代理未配置！请先执行选项 4 配置 Socks5 代理信息。");
                    return Ok(());
                }
                if cfg.vpn2.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: 出口 WARP 未配置！请先执行选项 6 自动注册或选项 5 粘贴 WARP。");
                    return Ok(());
                }
            }
            ProxyMode::StandaloneWg => {
                if cfg.vpn1.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: WireGuard 节点未配置！请先执行选项 3 导入 WireGuard。");
                    return Ok(());
                }
            }
            ProxyMode::StandaloneSocks => {
                if cfg.socks5.is_none() {
                    println!("❌ 错误: Socks5 代理未配置！请先执行选项 4 配置 Socks5 代理信息。");
                    return Ok(());
                }
            }
            ProxyMode::StandaloneWarp => {
                if cfg.vpn2.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: 出口 WARP 未配置！请先执行选项 6 自动注册或选项 5 粘贴 WARP。");
                    return Ok(());
                }
            }
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
        println!("   • 当前运行模式 : {}", working_cfg.mode.description());
        println!("   • 本地配置存储 : /var/lib/chainproxy/config.json");
        println!("--------------------------------------------------------------");

        // 显示入口 VPN 1
        println!(" 【前置入口 1: WireGuard 节点】");
        if working_cfg.vpn1.wireguard_config.trim().is_empty() {
            println!("   • 状态     : ❌ 未配置 (如需使用请按 3 导入)");
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

        // 显示 Socks5
        println!("\n 【前置入口 2: Socks5 代理节点】");
        if let Some(ref s5) = working_cfg.socks5 {
            println!("   • 状态     : ✅ 已配置就绪");
            println!("   • 代理地址 : {}:{}", s5.server, s5.port);
            if let Some(ref u) = s5.username {
                println!("   • 认证用户 : {}", u);
            }
            if s5.password.is_some() {
                println!("   • 认证密码 : ******** (已安全掩码保护)");
            }
            println!("   • 安全连接 : {}", s5.redacted_string());
        } else {
            println!("   • 状态     : ❌ 未配置 (如需使用请按 4 导入)");
        }

        // 显示出口 WARP
        println!("\n 【出口节点: Cloudflare WARP (VPN 2)】");
        if working_cfg.vpn2.wireguard_config.trim().is_empty() {
            println!("   • 状态     : ❌ 未配置 (请按 6 一键自动注册或按 5 手动粘贴)");
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
        println!("   • 出站路由拓扑   : {}", match working_cfg.mode {
            ProxyMode::WgChainWarp => "WireGuard 前置隧道 -> WARP 双层嵌套出站",
            ProxyMode::SocksChainWarp => "Socks5 前置中继 -> WARP 链式封装出站",
            ProxyMode::StandaloneWg => "WireGuard 单独直连出站",
            ProxyMode::StandaloneSocks => "Socks5 单独直连出站",
            ProxyMode::StandaloneWarp => "Cloudflare WARP 单独直连出站",
        });
        println!("==============================================================");

        print!("\n是否查看完整 WireGuard 原始配置？(1: 入口WG, 2: 出口WARP, 回车返回): ");
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
