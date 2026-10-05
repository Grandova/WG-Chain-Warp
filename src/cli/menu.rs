use crate::error::{ChainError, Result};
use crate::health::diagnose::SystemDiagnostician;
use crate::model::config::{ChainProxyConfig, ProxyMode};
use crate::model::state::{ChainStatus, TestReport};
use crate::network::gateway_monitor::GatewayMonitor;
use crate::network::iproute::IpRouteManager;
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

        ChainProxyConfig::default()
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

            print!("请选择操作编号 [0-13]: ");
            io::stdout().flush().unwrap();

            let mut choice = String::new();
            if reader.read_line(&mut choice).is_err() {
                break;
            }

            let choice = choice.trim();
            match choice {
                "1" | "apply" | "start" => {
                    self.apply_configuration().await?;
                }
                "2" | "test" => {
                    self.run_test(&mut reader).await;
                }
                "3" | "stop" => {
                    self.stop_service().await;
                }
                "4" | "m" | "M" | "mode" => {
                    self.switch_proxy_mode(&mut reader).await?;
                }
                "5" | "wg" => {
                    self.configure_wireguard(&mut reader).await?;
                }
                "6" | "s5" | "S5" | "socks" => {
                    self.configure_socks5(&mut reader).await?;
                }
                "7" | "warp" => {
                    self.configure_warp(&mut reader).await?;
                }
                "8" | "gw" | "gateway" => {
                    self.configure_gateway(&mut reader).await?;
                }
                "9" | "c" | "C" | "cfg" => {
                    self.view_config(&mut reader).await?;
                }
                "10" | "log" | "logs" => {
                    self.manage_logs(&mut reader).await?;
                }
                "11" | "diag" => {
                    self.diagnose();
                }
                "12" | "rb" | "rollback" => {
                    self.rollback().await;
                }
                "13" | "s" | "S" | "restart" => {
                    self.restart_daemon().await;
                }
                "status" => {
                    self.show_status().await;
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
            .timeout(std::time::Duration::from_millis(3000))
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
        println!("             chainproxy 多模式网络代理管理面板 (v{})       ", env!("CARGO_PKG_VERSION"));
        println!("==============================================================");

        let working_cfg = self.load_working_config();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(3000))
            .build()
            .unwrap_or_default();
        let status_url = format!("{}/api/v1/status", self.api_url);
        let mut daemon_connected = false;

        if let Ok(resp) = client.get(&status_url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(data) = json.get("data") {
                    let raw_state = data.get("state").and_then(|s| s.as_str()).unwrap_or("Unknown");
                    let state_desc = match raw_state {
                        "Running" => "🟢 运行中 (Running)",
                        "Stopped" => "⚪ 已停止 (Stopped)",
                        "Starting" => "🟡 启动中 (Starting)",
                        "Failed" => "🔴 启动失败 (Failed)",
                        "RollingBack" => "🟠 自动回滚中 (RollingBack)",
                        "Degraded" => "🟡 降级运行 (Degraded)",
                        _ => raw_state,
                    };
                    let visual = data.get("chain_visual").and_then(|v| v.as_str()).unwrap_or("");
                    let ver = data.get("active_config_version").and_then(|v| v.as_str()).unwrap_or("none");
                    println!(" 服务状态: {:<18} 活跃版本: {}", state_desc, ver);
                    println!(" 当前模式: {}", working_cfg.mode.description());
                    println!(" 日志级别: 【{}】 (按 [10] 可动态调节或切换为 debug 深度排错)", working_cfg.log_level);
                    println!(" 链路拓扑: {}", visual);
                    daemon_connected = true;
                }
            }
        }

        if !daemon_connected {
            println!(" 当前模式: {}", working_cfg.mode.description());
            println!(" 日志级别: 【{}】", working_cfg.log_level);
            println!(" 服务状态: ⚪ 后台服务未运行或连接中 (如需手动启动: systemctl start chainproxy)");
        }

        let uplink_info = IpRouteManager::detect_default_uplink().ok();
        let iface = working_cfg.uplink_interface.as_deref()
            .or(uplink_info.as_ref().map(|u| u.interface.as_str()));
        let detected_lan = iface.and_then(|iface| {
            Some((IpRouteManager::get_interface_ipv4(iface).ok()?.to_string(),
                IpRouteManager::get_interface_lan_subnet(iface)?))
        });

        if working_cfg.is_forwarding_enabled() {
            let (lan_ip, lan_sub) = detected_lan.as_ref().map(|(ip, sub)| (ip.as_str(), sub.as_str())).unwrap_or(("未探测", "未探测"));
            let eff_subnets = working_cfg.get_effective_forwarded_subnets(detected_lan.as_ref().map(|(_, s)| s.as_str()));
            let sub_desc = if eff_subnets.is_empty() { lan_sub.to_string() } else { eff_subnets.join(", ") };
            println!(" 局域网网关: 🟢 已开启 [网关IP: {} | 允许网段: {}]", lan_ip, sub_desc);
        } else {
            let (lan_ip, lan_sub) = detected_lan.as_ref().map(|(ip, sub)| (ip.as_str(), sub.as_str())).unwrap_or(("未探测", "未探测"));
            println!(" 局域网网关: ⚪ 已关闭 (按 [8] 可开启 | 本机IP: {} 网段: {})", lan_ip, lan_sub);
        }
        println!("--------------------------------------------------------------");

        // Dynamic hint for required nodes under active mode
        let need_hint = match working_cfg.mode {
            ProxyMode::WgChainWarp => {
                let wg_ok = !working_cfg.vpn1.wireguard_config.trim().is_empty();
                let warp_ok = !working_cfg.vpn2.wireguard_config.trim().is_empty();
                if !wg_ok && !warp_ok {
                    "⚠️  需配置: 请先按 [5] 导入 WireGuard 节点，按 [7] 注册 WARP 出口".to_string()
                } else if !wg_ok {
                    "⚠️  需配置: 请按 [5] 导入 WireGuard 节点".to_string()
                } else if !warp_ok {
                    "⚠️  需配置: 请按 [7] 自动注册或配置 Cloudflare WARP 出口".to_string()
                } else {
                    "✅ 所需节点全部就绪！请按 [1] 应用配置并启动服务".to_string()
                }
            }
            ProxyMode::SocksChainWarp => {
                let s5_ok = working_cfg.socks5.is_some();
                let warp_ok = !working_cfg.vpn2.wireguard_config.trim().is_empty();
                if !s5_ok && !warp_ok {
                    "⚠️  需配置: 请先按 [6] 导入 Socks5 代理，按 [7] 注册 WARP 出口".to_string()
                } else if !s5_ok {
                    "⚠️  需配置: 请按 [6] 导入 Socks5 代理信息".to_string()
                } else if !warp_ok {
                    "⚠️  需配置: 请按 [7] 自动注册或配置 Cloudflare WARP 出口".to_string()
                } else {
                    "✅ 所需节点全部就绪！请按 [1] 应用配置并启动服务".to_string()
                }
            }
            ProxyMode::StandaloneWg => {
                let wg_ok = !working_cfg.vpn1.wireguard_config.trim().is_empty();
                if !wg_ok {
                    "⚠️  需配置: 请按 [5] 导入 WireGuard 节点".to_string()
                } else {
                    "✅ WireGuard 节点已就绪！请按 [1] 应用配置并启动服务".to_string()
                }
            }
            ProxyMode::StandaloneSocks => {
                let s5_ok = working_cfg.socks5.is_some();
                if !s5_ok {
                    "⚠️  需配置: 请按 [6] 导入 Socks5 代理信息".to_string()
                } else {
                    "✅ Socks5 代理已就绪！请按 [1] 应用配置并启动服务".to_string()
                }
            }
            ProxyMode::StandaloneWarp => {
                let warp_ok = !working_cfg.vpn2.wireguard_config.trim().is_empty();
                if !warp_ok {
                    "⚠️  需配置: 请按 [7] 自动注册或配置 Cloudflare WARP 出口".to_string()
                } else {
                    "✅ WARP 出口已就绪！请按 [1] 应用配置并启动服务".to_string()
                }
            }
        };
        if !need_hint.is_empty() {
            println!(" 准备状态: {}", need_hint);
            println!("--------------------------------------------------------------");
        }

        println!("【常用控制】");
        println!("  1. 应用配置并启动服务 (Apply & Start)");
        println!("  2. 全链路连通性与分跳测试 (Test & Verify)");
        println!("  3. 停止代理服务并恢复网络 (Stop & Cleanup)");
        println!("  4. 切换代理运行模式 (Switch Mode)");
        println!();
        println!("【节点、出口与网关配置】");
        println!("  5. 配置 WireGuard 节点 (导入或编辑 .conf / INI)");
        println!("  6. 配置 Socks5 代理节点 (直接输入 IP:端口 或 带账密链接)");
        println!("  7. 配置 Cloudflare WARP 出口 (一键自动注册 / 手动配置)");
        let gw_hint = if working_cfg.is_forwarding_enabled() { "🟢 开启" } else { "⚪ 关闭" };
        println!("  8. 局域网透明网关管理 (LAN Gateway) [当前: {}]", gw_hint);
        println!("  9. 查看当前所有节点与网关详情 (View Config)");
        println!();
        println!("【运维与诊断】");
        println!(" 10. 服务实时日志与日志等级管理 (View Logs & Log Level)");
        println!(" 11. 一键系统与网络诊断 (Diagnose)");
        println!(" 12. 回滚至上一版本配置 (Rollback)");
        println!(" 13. 重启后台守护服务 (Restart Daemon)");
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
                            println!("💡 提示: 检测到尚未配置 Socks5 节点，请按 [6] 输入 Socks5 代理信息。");
                        }
                    }
                    ProxyMode::WgChainWarp | ProxyMode::StandaloneWg => {
                        if cfg.vpn1.wireguard_config.trim().is_empty() {
                            println!("💡 提示: 检测到尚未配置 WireGuard 节点，请按 [5] 导入 WireGuard 节点。");
                        }
                    }
                    ProxyMode::StandaloneWarp => {
                        if cfg.vpn2.wireguard_config.trim().is_empty() {
                            println!("💡 提示: 检测到尚未配置 WARP 出口，请按 [7] 配置或自动注册 WARP。");
                        }
                    }
                }
                println!("💡 提示: 模式变更后，请按 [1] 应用配置并启动生效。");
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

                match cfg.mode {
                    ProxyMode::SocksChainWarp => {
                        if cfg.vpn2.wireguard_config.trim().is_empty() {
                            println!("💡 提示: 当前为 Socks5 -> WARP 链式模式，请继续按 [7] 配置出口 WARP，最后按 [1] 启动生效。");
                        } else {
                            println!("💡 提示: 节点已全部就绪！请按 [1] 应用配置并启动服务。");
                        }
                    }
                    ProxyMode::StandaloneSocks => {
                        println!("💡 提示: 当前为单独 Socks5 出站模式，请按 [1] 应用配置并启动服务。");
                    }
                    _ => {
                        println!("💡 提示: 请按 [1] 应用配置并启动服务。");
                    }
                }
            }
            Err(e) => {
                println!("\n❌ Socks5 格式解析失败: {}", e);
            }
        }

        Ok(())
    }

    async fn configure_wireguard<R: BufRead>(&self, reader: &mut R) -> Result<()> {
        println!("\n--- [配置 WireGuard 节点] ---");
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
                println!("\n✅ WireGuard 节点解析成功！");
                println!("- 本地地址 (Address): {:?}", parsed.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>());
                if !parsed.interface.dns.is_empty() {
                    println!("- DNS 服务器: {:?}", parsed.interface.dns);
                }
                if let Some(peer) = parsed.peers.first() {
                    if let Some(ref ep) = peer.endpoint {
                        println!("- 对端端点 (Endpoint): {}:{}", ep.host, ep.port);
                    }
                    println!("- 对端公钥 (PublicKey): {}", peer.public_key);
                    println!("- 保活周期 (Keepalive): {:?}", peer.persistent_keepalive);
                }

                let mut cfg = self.load_working_config();
                cfg.vpn1.wireguard_config = raw_conf;
                self.save_working_config(&cfg)?;
                println!("💾 WireGuard 配置已保存就绪！");

                match cfg.mode {
                    ProxyMode::WgChainWarp => {
                        if cfg.vpn2.wireguard_config.trim().is_empty() {
                            println!("💡 提示: 当前为双层链式模式，请继续按 [7] 配置出口 WARP，最后按 [1] 启动生效。");
                        } else {
                            println!("💡 提示: 节点已全部就绪！请按 [1] 应用配置并启动服务。");
                        }
                    }
                    ProxyMode::StandaloneWg => {
                        println!("💡 提示: 当前为单独 WireGuard 出站模式，请按 [1] 应用配置并启动服务。");
                    }
                    _ => {
                        println!("💡 提示: 若需使用此 WireGuard 节点，请确认当前运行模式 (按 [4] 切换)，然后按 [1] 启动。");
                    }
                }
            }
            Err(e) => {
                println!("\n❌ 配置解析失败: {}", e);
            }
        }

        Ok(())
    }

    async fn configure_warp<R: BufRead>(&self, reader: &mut R) -> Result<()> {
        println!("\n==============================================================");
        println!("                配置出口 Cloudflare WARP                      ");
        println!("==============================================================");
        println!(" 选项列表：");
        println!("   1. 一键自动注册官方 WARP 节点 (推荐，无需填写任何凭据)");
        println!("   2. 手动粘贴已有 WARP 的 WireGuard 配置文本 (.conf / INI)");
        println!("--------------------------------------------------------------");
        print!("请选择配置方式 [1-2] (回车默认 1，输入 0 取消): ");
        let _ = io::stdout().flush();

        let mut choice = String::new();
        if reader.read_line(&mut choice).is_err() {
            return Ok(());
        }
        let choice = choice.trim();
        match choice {
            "1" | "" => {
                self.configure_vpn2_auto_warp().await?;
            }
            "2" => {
                self.configure_vpn2_manual(reader).await?;
            }
            "0" => {
                println!("已取消操作。");
            }
            _ => {
                println!("无效输入，已取消。");
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
                println!("💡 提示: 请按 [1] 应用配置并启动服务。");
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
                println!("💾 已成功将 WARP 绑定为出口！");
                println!("💡 提示: 节点已就绪！请按 [1] 应用配置并启动服务。");
            }
            Err(e) => {
                println!("\n❌ 自动注册失败: {}", e);
            }
        }

        Ok(())
    }

    async fn configure_gateway<R: io::BufRead>(&self, reader: &mut R) -> Result<()> {
        let mut working_cfg = self.load_working_config();
        let uplink_info = IpRouteManager::detect_default_uplink().ok();
        let iface = working_cfg.uplink_interface.as_deref()
            .or(uplink_info.as_ref().map(|u| u.interface.as_str()))
            .unwrap_or("eth0");
        let local_ip = IpRouteManager::get_interface_ipv4(iface).ok();
        let auto_lan_subnet = IpRouteManager::get_interface_lan_subnet(iface);

        loop {
            let status_str = if working_cfg.is_forwarding_enabled() {
                "🟢 已开启 (同局域网客户端可将网关设置为本机IP走代理出站)"
            } else {
                "⚪ 已关闭 (LAN 保留普通转发策略)"
            };
            let ip_str = local_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "未探测到".to_string());
            let auto_sub_str = auto_lan_subnet.clone().unwrap_or_else(|| "未探测到".to_string());
            let eff_subnets = working_cfg.get_effective_forwarded_subnets(auto_lan_subnet.as_deref());
            let eff_str = if eff_subnets.is_empty() { "无".to_string() } else { eff_subnets.join(", ") };

            println!("\n==============================================================");
            println!("                 局域网透明网关 (LAN Gateway) 设置            ");
            println!("==============================================================");
            println!(" 网关状态: {}", status_str);
            println!(" 本机物理网卡: {}", iface);
            println!(" 本机局域网 IP: {}  <-- [同局域网设备网关请填写此 IP]", ip_str);
            println!(" 自动允许实际网段: {} (开关: {})", auto_sub_str, if working_cfg.gateway.auto_allow_lan { "已启用" } else { "未启用" });
            println!(" 自定义允许网段: {:?}", working_cfg.gateway.allowed_subnets);
            println!(" 当前生效放行网段: {}", eff_str);
            println!("--------------------------------------------------------------");
            println!("  1. 开启局域网网关 (自动放行本机实际网段同局域网设备)");
            println!("  2. 关闭局域网网关 (保持本机代理开关不变)");
            println!("  3. 切换自动允许本机实际网段 [当前: {}]", if working_cfg.gateway.auto_allow_lan { "开启" } else { "关闭" });
            println!("  4. 添加/管理自定义允许网段 (CIDR 格式)");
            println!("  5. 局域网网关体征全面体检与人话诊断报告 (Gateway Diagnostics)");
            println!("  6. 查看近期局域网数据流与 DNS 拦截记录 (LAN Events)");
            println!("  7. 查看同局域网设备 (电脑/手机/电视/软路由) 网关与 DNS 设置教学");
            println!("  0. 返回上级菜单");
            println!("==============================================================");
            print!("请选择操作 [0-7]: ");
            io::stdout().flush().unwrap();

            let mut choice = String::new();
            if reader.read_line(&mut choice).is_err() {
                break;
            }
            let choice = choice.trim();

            match choice {
                "1" => {
                    working_cfg.gateway.enabled = true;
                    working_cfg.routing.proxy_forwarded_outbound = true;
                    working_cfg.gateway.auto_allow_lan = true;
                    self.save_working_config(&working_cfg)?;
                    println!("\n✅ 局域网透明网关已开启！");
                    if let Some(ref sub) = auto_lan_subnet {
                        println!("💡 已自动允许局域网网段: {}", sub);
                    }
                    if let Some(ref ip) = local_ip {
                        println!("💡 同局域网机器请将「默认网关」与「DNS」设置为本机 IP: {}", ip);
                    }

                    print!("\n是否立即将新配置应用生效？[Y/n]: ");
                    io::stdout().flush().unwrap();
                    let mut apply_choice = String::new();
                    let _ = reader.read_line(&mut apply_choice);
                    let apply_choice = apply_choice.trim();
                    if apply_choice.is_empty() || apply_choice.eq_ignore_ascii_case("y") {
                        self.apply_configuration().await?;
                    }
                    break;
                }
                "2" => {
                    working_cfg.gateway.enabled = false;
                    working_cfg.routing.proxy_forwarded_outbound = false;
                    self.save_working_config(&working_cfg)?;
                    println!("\n⚪ 局域网透明网关已关闭！");

                    print!("\n是否立即将新配置应用生效？[Y/n]: ");
                    io::stdout().flush().unwrap();
                    let mut apply_choice = String::new();
                    let _ = reader.read_line(&mut apply_choice);
                    let apply_choice = apply_choice.trim();
                    if apply_choice.is_empty() || apply_choice.eq_ignore_ascii_case("y") {
                        self.apply_configuration().await?;
                    }
                    break;
                }
                "3" => {
                    working_cfg.gateway.auto_allow_lan = !working_cfg.gateway.auto_allow_lan;
                    self.save_working_config(&working_cfg)?;
                    println!("\n已将自动允许实际网段设置为: {}", if working_cfg.gateway.auto_allow_lan { "开启" } else { "关闭" });
                }
                "4" => {
                    println!("\n--- [管理自定义允许网段] ---");
                    println!("当前自定义网段: {:?}", working_cfg.gateway.allowed_subnets);
                    println!("  1. 添加新网段 (例如 192.168.2.0/24 或 10.0.0.0/24)");
                    println!("  2. 清空所有自定义网段");
                    println!("  0. 取消并返回");
                    print!("请选择 [0-2]: ");
                    io::stdout().flush().unwrap();
                    let mut sub_ch = String::new();
                    let _ = reader.read_line(&mut sub_ch);
                    match sub_ch.trim() {
                        "1" => {
                            print!("请输入要允许的网段 CIDR: ");
                            io::stdout().flush().unwrap();
                            let mut new_cidr = String::new();
                            let _ = reader.read_line(&mut new_cidr);
                            let new_cidr = new_cidr.trim();
                            if new_cidr.parse::<ipnet::IpNet>().is_ok() {
                                if !working_cfg.gateway.allowed_subnets.contains(&new_cidr.to_string()) {
                                    working_cfg.gateway.allowed_subnets.push(new_cidr.to_string());
                                    self.save_working_config(&working_cfg)?;
                                    println!("✅ 已添加网段: {}", new_cidr);
                                } else {
                                    println!("提示: 该网段已存在。");
                                }
                            } else {
                                println!("❌ 无效的 CIDR 格式 (示例: 192.168.10.0/24)");
                            }
                        }
                        "2" => {
                            working_cfg.gateway.allowed_subnets.clear();
                            self.save_working_config(&working_cfg)?;
                            println!("✅ 已清空自定义允许网段。");
                        }
                        _ => {}
                    }
                }
                "5" => {
                    self.show_gateway_diagnostics(&working_cfg, iface, local_ip.as_ref().map(|i| i.to_string()).as_deref()).await;
                    println!("\n按回车键继续...");
                    let mut dummy = String::new();
                    let _ = reader.read_line(&mut dummy);
                }
                "6" => {
                    self.show_gateway_events(&working_cfg).await;
                    println!("\n按回车键继续...");
                    let mut dummy = String::new();
                    let _ = reader.read_line(&mut dummy);
                }
                "7" => {
                    let gw_ip = local_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "192.168.x.x (本机IP)".to_string());
                    println!("\n==============================================================");
                    println!("           同局域网客户端 (电脑/手机/电视/软路由) 设置教学       ");
                    println!("==============================================================");
                    println!("要想让同局域网内的其它设备（Windows / Mac / iPhone / Android / 电视盒子）");
                    println!("所有流量通过本机的 WireGuard / WARP 代理出海，只需在客户端设置静态网络：");
                    println!();
                    println!("【步骤 1】打开客户端的「网络设置」-> 找到当前连接的 Wi-Fi 或以太网");
                    println!("【步骤 2】将 IP 设置由「DHCP (自动获取)」改为「静态 (手动 / Static)」");
                    println!("【步骤 3】填写网络参数：");
                    println!("  • IP 地址: 与本机同一局域网网段未被占用的 IP (例如 192.168.1.188)");
                    println!("  • 子网掩码: 使用所在局域网的实际前缀");
                    println!("  • 默认网关 (Gateway): {} <-- 本机局域网 IP", gw_ip);
                    println!("  • 首选 DNS: {} (自动经由本机防泄漏 DNS 加密解析)", gw_ip);
                    println!("  • 备用 DNS: 1.1.1.1 或 8.8.8.8 (或留空)");
                    println!("【步骤 4】保存设置。");
                    println!();
                    println!("⚠️【重要排错提示】如果客户端能 ping 通网关但报 'Could not resolve host'：");
                    println!("原因是客户端的 /etc/resolv.conf 仍保留着云厂商内网 DNS (如 10.82.160.1)，");
                    println!("同子网广播 ARP 直连旧路由，完全绕过了本机网关！");
                    println!("👉 只需在客户端执行: echo 'nameserver 1.1.1.1' > /etc/resolv.conf 即可秒解！");
                    println!("==============================================================");
                    println!("\n按回车键返回设置菜单...");
                    let mut dummy = String::new();
                    let _ = reader.read_line(&mut dummy);
                }
                "0" | "q" | "exit" => {
                    break;
                }
                _ => {
                    println!("\n无效选项，请重新输入！");
                }
            }
        }

        Ok(())
    }

    async fn apply_configuration(&self) -> Result<()> {
        let cfg = self.load_working_config();
        println!("\n--- [应用配置并启动服务] ---");
        println!("当前生效模式: {}", cfg.mode.description());

        match cfg.mode {
            ProxyMode::WgChainWarp => {
                if cfg.vpn1.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: 入口 WireGuard 未配置！请先按 [5] 导入 WireGuard 节点。");
                    return Ok(());
                }
                if cfg.vpn2.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: 出口 WARP 未配置！请先按 [7] 自动注册或配置 WARP。");
                    return Ok(());
                }
            }
            ProxyMode::SocksChainWarp => {
                if cfg.socks5.is_none() {
                    println!("❌ 错误: 入口 Socks5 代理未配置！请先按 [6] 配置 Socks5 代理信息。");
                    return Ok(());
                }
                if cfg.vpn2.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: 出口 WARP 未配置！请先按 [7] 自动注册或配置 WARP。");
                    return Ok(());
                }
            }
            ProxyMode::StandaloneWg => {
                if cfg.vpn1.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: WireGuard 节点未配置！请先按 [5] 导入 WireGuard 节点。");
                    return Ok(());
                }
            }
            ProxyMode::StandaloneSocks => {
                if cfg.socks5.is_none() {
                    println!("❌ 错误: Socks5 代理未配置！请先按 [6] 配置 Socks5 代理信息。");
                    return Ok(());
                }
            }
            ProxyMode::StandaloneWarp => {
                if cfg.vpn2.wireguard_config.trim().is_empty() {
                    println!("❌ 错误: 出口 WARP 未配置！请先按 [7] 自动注册或配置 WARP。");
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
            println!("\n⚠️  [检测] 未找到能正常执行的 sing-box（可能未安装或安装已损坏）。");
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
                println!("安装完成后重新进入面板按 [1] 即可启动链路。");
                return Ok(());
            }
        }

        println!("正在向后台发送事务 Apply 请求 (包含 30 秒看门狗与入站回程保护)...");
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
                    println!("\n❌ 应用失败: {}", json.get("error").and_then(|e| e.as_str()).unwrap_or("未知错误"));
                    println!("💡 请根据上方错误处理；可运行 chainproxy diagnose 检查路由及恢复状态。");
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

        let working_cfg = self.load_working_config();
        if !is_running || active_version.is_none() {
            println!("\n⚠️  [提示] 代理服务当前未处于运行状态 (尚未启动生效)！");
            println!("由于服务尚未启动，sing-box 本地链路探测端口尚未开启。");
            println!("\n💡 建议操作流程：");
            match working_cfg.mode {
                ProxyMode::WgChainWarp => {
                    println!("  1. 按 [5] 导入 WireGuard 节点");
                    println!("  2. 按 [7] 自动注册或配置 Cloudflare WARP 出口");
                    println!("  3. 按 [1] 应用配置并启动服务 (Apply & Start)");
                    println!("  4. 服务启动成功后，再按 [2] 进行连通性探测验证！");
                }
                ProxyMode::SocksChainWarp => {
                    println!("  1. 按 [6] 配置 Socks5 代理节点");
                    println!("  2. 按 [7] 自动注册或配置 Cloudflare WARP 出口");
                    println!("  3. 按 [1] 应用配置并启动服务 (Apply & Start)");
                    println!("  4. 服务启动成功后，再按 [2] 进行连通性探测验证！");
                }
                ProxyMode::StandaloneWg => {
                    println!("  1. 按 [5] 导入 WireGuard 节点");
                    println!("  2. 按 [1] 应用配置并启动服务 (Apply & Start)");
                    println!("  3. 服务启动成功后，再按 [2] 进行连通性探测验证！");
                }
                ProxyMode::StandaloneSocks => {
                    println!("  1. 按 [6] 配置 Socks5 代理节点");
                    println!("  2. 按 [1] 应用配置并启动服务 (Apply & Start)");
                    println!("  3. 服务启动成功后，再按 [2] 进行连通性探测验证！");
                }
                ProxyMode::StandaloneWarp => {
                    println!("  1. 按 [7] 自动注册或配置 Cloudflare WARP 出口");
                    println!("  2. 按 [1] 应用配置并启动服务 (Apply & Start)");
                    println!("  3. 服务启动成功后，再按 [2] 进行连通性探测验证！");
                }
            }
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
            .timeout(std::time::Duration::from_millis(3000))
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
        println!(" 【WireGuard 节点配置】");
        if working_cfg.vpn1.wireguard_config.trim().is_empty() {
            println!("   • 状态     : ❌ 未配置 (如需使用请按 [5] 配置)");
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
        println!("\n 【Socks5 代理节点配置】");
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
            println!("   • 状态     : ❌ 未配置 (如需使用请按 [6] 配置)");
        }

        // 显示出口 WARP
        println!("\n 【Cloudflare WARP 出口配置】");
        if working_cfg.vpn2.wireguard_config.trim().is_empty() {
            println!("   • 状态     : ❌ 未配置 (如需使用请按 [7] 配置或自动注册)");
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

        // 显示局域网透明网关
        println!("\n 【局域网透明网关 (LAN Gateway)】");
        let uplink_info = IpRouteManager::detect_default_uplink().ok();
        let iface = working_cfg.uplink_interface.as_deref()
            .or(uplink_info.as_ref().map(|u| u.interface.as_str()))
            .unwrap_or("eth0");
        let local_ip = IpRouteManager::get_interface_ipv4(iface).ok();
        let auto_sub = IpRouteManager::get_interface_lan_subnet(iface);
        let eff_subnets = working_cfg.get_effective_forwarded_subnets(auto_sub.as_deref());
        println!("   • 网关状态 : {}", if working_cfg.is_forwarding_enabled() { "🟢 已开启 (同局域网设备设置本机IP为网关即可走代理出站)" } else { "⚪ 已关闭 (LAN 保留普通转发策略)" });
        println!("   • 本机网卡 : {}", iface);
        println!("   • 网关 IP  : {}", local_ip.map(|i| i.to_string()).unwrap_or_else(|| "未探测".to_string()));
        println!("   • 自动网段 : {} (自动匹配本机所属网段: {})", auto_sub.unwrap_or_else(|| "未探测".to_string()), if working_cfg.gateway.auto_allow_lan { "已启用" } else { "未启用" });
        println!("   • 生效网段 : {}", if eff_subnets.is_empty() { "无".to_string() } else { eff_subnets.join(", ") });

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

    async fn show_gateway_diagnostics(&self, cfg: &ChainProxyConfig, iface: &str, local_ip: Option<&str>) {
        println!("\n正在执行局域网透明网关深度体检诊断...");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();
        let url = format!("{}/api/v1/gateway/diagnose", self.api_url);
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(report) = json.get("data").and_then(|d| d.as_str()) {
                    println!("{}", report);
                    return;
                }
            }
        }

        // Local fallback if daemon not responding
        let detected = IpRouteManager::get_interface_lan_subnet(iface);
        let subnets = cfg.get_effective_forwarded_subnets(detected.as_deref());
        let report = GatewayMonitor::generate_human_diagnostics(iface, &subnets, local_ip, cfg.is_forwarding_enabled());
        println!("{}", report);
    }

    async fn show_gateway_events(&self, cfg: &ChainProxyConfig) {
        println!("\n正在获取近期局域网数据流与 DNS 拦截记录...");
        println!("--------------------------------------------------------------");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();
        let url = format!("{}/api/v1/gateway/events", self.api_url);
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(events) = json.get("data").and_then(|d| d.as_array()) {
                    if events.is_empty() {
                        println!("(暂未捕获到局域网设备数据流或 sing-box 日志记录)");
                    } else {
                        for ev in events {
                            if let Some(s) = ev.as_str() {
                                println!("{}", s);
                            }
                        }
                    }
                    println!("--------------------------------------------------------------");
                    println!("💡 提示: 若需查看包含底层原始数据包的全部实时日志，请按 [10] -> [2] 实时跟踪。");
                    return;
                }
            }
        }

        // Local fallback
        let events = GatewayMonitor::get_recent_lan_events(&cfg.routing.forwarded_subnets, 30);
        if events.is_empty() {
            println!("(暂未捕获到局域网设备数据流或 /var/lib/chainproxy/singbox.log 为空)");
        } else {
            for ev in events {
                println!("{}", ev);
            }
        }
        println!("--------------------------------------------------------------");
        println!("💡 提示: 若需查看包含底层原始数据包的全部实时日志，请按 [10] -> [2] 实时跟踪。");
    }

    async fn manage_logs<R: BufRead>(&self, reader: &mut R) -> Result<()> {
        let mut working_cfg = self.load_working_config();
        let uplink_info = IpRouteManager::detect_default_uplink().ok();
        let iface = working_cfg.uplink_interface.as_deref()
            .or(uplink_info.as_ref().map(|u| u.interface.as_str()))
            .unwrap_or("eth0");
        let local_ip = uplink_info.as_ref().and_then(|u| u.local_ip).map(|i| i.to_string());

        loop {
            // Try to query daemon's active log level
            let active_level = {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_millis(1500))
                    .build()
                    .unwrap_or_default();
                let url = format!("{}/api/v1/log_level", self.api_url);
                if let Ok(resp) = client.get(&url).send().await {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        json.get("data").and_then(|d| d.as_str()).map(|s| s.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }.unwrap_or_else(|| working_cfg.log_level.clone());

            println!("\n==============================================================");
            println!("                 chainproxy 日志监控与等级管理中心            ");
            println!("==============================================================");
            println!(" 当前日志等级: 【{}】 [可选: none / info / warn / debug]", active_level);
            println!(" 日志接入状态: sing-box 进程输出已实时重定向至系统 journalctl 守护日志");
            println!("--------------------------------------------------------------");
            println!("  1. 查看最新运行日志 (最近 40 行，包含 sing-box 与守护进程)");
            println!("  2. 实时滚动跟踪全部日志 (流式查看：可按 Ctrl+C 随时退出)");
            println!("  3. 切换日志输出级别 (none / info / warn / debug)");
            println!("  4. 局域网透明网关诊断与体征报告 (人话版排错指南)");
            println!("  5. 查看局域网近期数据包拦截与转发记录");
            println!("  0. 返回主菜单");
            println!("==============================================================");
            print!("请选择操作编号 [0-5]: ");
            io::stdout().flush().unwrap();

            let mut choice = String::new();
            if reader.read_line(&mut choice).is_err() {
                break;
            }
            let choice = choice.trim();

            match choice {
                "1" => {
                    self.view_recent_logs().await;
                    println!("\n按回车键继续...");
                    let mut dummy = String::new();
                    let _ = reader.read_line(&mut dummy);
                }
                "2" => {
                    #[cfg(target_os = "linux")]
                    {
                        println!("\n正在启动实时日志跟踪 (按 Ctrl+C 即可停止日志跟踪并返回菜单)...");
                        println!("--------------------------------------------------------------");
                        let _ = std::process::Command::new("journalctl")
                            .args(["-u", "chainproxy", "-f"])
                            .status();
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        println!("\n当前非 Linux 系统，无法执行 journalctl。");
                        println!("请直接在终端启动 chainproxy daemon 查看实时控制台输出。");
                        println!("\n按回车键继续...");
                        let mut dummy = String::new();
                        let _ = reader.read_line(&mut dummy);
                    }
                }
                "3" => {
                    println!("\n--- [切换日志输出级别] ---");
                    println!("当前日志级别: {}", active_level);
                    println!("说明：");
                    println!("  • debug : 最详尽日志，包含所有 TCP/UDP 流量、DNS 劫持转发、底层连接细节 (推荐排错时使用)");
                    println!("  • info  : 标准运行日志，记录启动、配置生效、健康检查 (推荐生产环境使用)");
                    println!("  • warn  : 仅记录告警与致命错误");
                    println!("  • none  : 彻底静默，不记录日志");
                    println!("--------------------------------------------------------------");
                    println!("  1. 设置为 debug (排查网关与代理问题首选)");
                    println!("  2. 设置为 info  (默认推荐，日常运行)");
                    println!("  3. 设置为 warn  (仅告警与错误)");
                    println!("  4. 设置为 none  (静默模式)");
                    println!("  0. 取消并返回");
                    print!("请选择 [0-4]: ");
                    io::stdout().flush().unwrap();

                    let mut l_choice = String::new();
                    let _ = reader.read_line(&mut l_choice);
                    let target_lvl = match l_choice.trim() {
                        "1" => Some("debug"),
                        "2" => Some("info"),
                        "3" => Some("warn"),
                        "4" => Some("none"),
                        _ => None,
                    };

                    if let Some(lvl) = target_lvl {
                        working_cfg.log_level = lvl.to_string();
                        self.save_working_config(&working_cfg)?;

                        let client = reqwest::Client::new();
                        let url = format!("{}/api/v1/log_level", self.api_url);
                        let payload = serde_json::json!({ "level": lvl });
                        let daemon_synced = match client.post(&url).json(&payload).send().await {
                            Ok(resp) => resp.status().is_success(),
                            Err(_) => false,
                        };

                        if daemon_synced {
                            println!("\n🎉 日志级别已成功切换为 【{}】 (后台守护服务已实时生效)！", lvl);
                        } else {
                            println!("\n💾 日志级别已保存为 【{}】 (将在下次应用配置或重启服务后生效)。", lvl);
                        }
                    }
                    println!("\n按回车键继续...");
                    let mut dummy = String::new();
                    let _ = reader.read_line(&mut dummy);
                }
                "4" => {
                    self.show_gateway_diagnostics(&working_cfg, iface, local_ip.as_deref()).await;
                    println!("\n按回车键继续...");
                    let mut dummy = String::new();
                    let _ = reader.read_line(&mut dummy);
                }
                "5" => {
                    self.show_gateway_events(&working_cfg).await;
                    println!("\n按回车键继续...");
                    let mut dummy = String::new();
                    let _ = reader.read_line(&mut dummy);
                }
                "0" | "q" | "exit" => {
                    break;
                }
                _ => {
                    println!("\n无效选项，请重新输入！");
                }
            }
        }

        Ok(())
    }

    async fn view_recent_logs(&self) {
        if !self.ensure_daemon_running().await {
            println!("\n❌ 无法连接守护进程 ({})", self.api_url);
            println!("提示: 请执行 'systemctl restart chainproxy' 并查看状态: 'systemctl status chainproxy'");
            return;
        }

        println!("\n正在获取最近运行日志 (最新 40 行)...");
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
        println!(" 总体探测结论: ✅ 链路全线畅通，代理服务正常运行！");
    } else {
        println!(" 总体探测结论: ⚠️  链路探测未完全通过 (可能尚未启动或节点不可达)");
    }
    println!("--------------------------------------------------------------");

    println!(" [1] 物理底层网络 (VPS 宿主机)");
    println!("     • 接口网卡 : {}", report.physical.name);
    println!("     • 默认网关 : {}", if report.physical.endpoint.is_empty() { "未检测到" } else { &report.physical.endpoint });
    println!("     • 连通状态 : {}", if report.physical.reachable { "✅ 正常 (UP)" } else { "❌ 异常" });

    let is_standalone = report.vpn2.status.contains("直连")
        || report.vpn2.endpoint == "None"
        || report.vpn2.name.contains("未使用");

    if is_standalone {
        let node_title = if report.vpn1.name.contains("Socks5") {
            "出口 Socks5 代理节点 (直连出站)"
        } else if report.vpn1.name.contains("WireGuard") || report.vpn1.name.contains("VPN") {
            "出口 WireGuard 节点 (直连出站)"
        } else {
            "出口代理节点 (直连出站)"
        };
        println!("\n [2] {}", node_title);
        println!("     • 节点名称 : {}", if report.vpn1.name.is_empty() { "默认代理节点" } else { &report.vpn1.name });
        println!("     • 对端端点 : {}", if report.vpn1.endpoint.is_empty() { "未配置" } else { &report.vpn1.endpoint });
        println!("     • 节点连通 : {}", if report.vpn1.reachable { "✅ 正常连接" } else { "❌ 连接失败" });
        if let Some(lat) = report.vpn1.latency_ms {
            println!("     • 节点延迟 : {} ms", lat);
        }
        if let Some(ref msg) = report.vpn1.message {
            println!("     • 探测详情 : {}", msg);
        }

        println!("\n [3] 最终公网出口 (Internet Egress)");
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
    } else {
        println!("\n [2] 第一跳: 入口节点 ({})", if report.vpn1.name.is_empty() { "前置中继" } else { &report.vpn1.name });
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
    }
    println!("==============================================================");

    if !report.success {
        println!("💡 排查建议:");
        println!("  - 若服务状态为 Stopped，请先按 [1] 应用配置并启动服务");
        println!("  - 若节点连接失败，请按 [8] 检查节点配置，或确认对端 Endpoint / 密钥 / 端口连通性");
        println!("  - 可按 [9] 查看最新运行日志以了解后台详细握手情况");
    }
}
