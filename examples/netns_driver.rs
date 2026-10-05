//! Linux namespace test driver. Uses the production generators and network managers.
use chainproxy::engine::transaction::{ChainEngine, NetworkSnapshot};
use chainproxy::model::config::ChainProxyConfig;
use chainproxy::network::{IpRouteManager, NftablesManager, SysctlManager};
use chainproxy::singbox::{generate_singbox_config, SingBoxManager};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let config: ChainProxyConfig = serde_json::from_slice(&std::fs::read(&args[2])?)?;
    let dir = PathBuf::from(&args[3]);
    std::fs::create_dir_all(&dir)?;
    if args[1] == "recover" {
        ChainEngine::new(&dir, "sing-box").stop()?;
        return Ok(());
    }
    if args[1] == "failure" {
        let mut engine = ChainEngine::new(&dir, "sing-box");
        engine.set_watchdog_timeout(1);
        assert!(engine.apply(config).await.is_err());
        engine.stop()?;
        return Ok(());
    }
    if args[1] == "engine" {
        let mut engine = ChainEngine::new(&dir, "sing-box");
        engine.set_watchdog_timeout(12);
        engine.apply(config).await?;
        println!("READY");
        std::io::stdout().flush()?;
        for line in std::io::stdin().lock().lines() {
            let line = line?;
            if line == "stop" {
                break;
            }
            let updated = serde_json::from_slice(&std::fs::read(line)?)?;
            let result = engine.apply(updated).await;
            println!(
                "{}",
                serde_json::json!({"success": result.is_ok(), "state": engine.get_status().state})
            );
            std::io::stdout().flush()?;
        }
        engine.stop()?;
        return Ok(());
    }
    let uplink = config.uplink_interface.as_deref().unwrap();
    let lans = IpRouteManager::lan_subnets(&config, uplink)?;
    let plan = IpRouteManager::route_plan(&config, &lans, &[])?;
    IpRouteManager::check_available(&plan)?;
    let snapshot = NetworkSnapshot::capture(plan, &config)?;
    let local_ip = IpRouteManager::get_interface_ipv4(uplink)?.to_string();
    let sb = generate_singbox_config(
        &config,
        &config.parse_and_validate()?,
        uplink,
        Some(&local_ip),
    )?;
    let path = dir.join("singbox.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&sb)?)?;
    SingBoxManager::check_config("sing-box", &path)?;
    let mut process = SingBoxManager::new();
    let result = (|| -> anyhow::Result<()> {
        let mut interfaces = vec![uplink.to_string()];
        interfaces.extend(lans.iter().map(|l| l.interface.clone()));
        interfaces.sort();
        interfaces.dedup();
        SysctlManager::configure_for_proxy(
            &interfaces,
            config.is_forwarding_enabled() && !lans.is_empty(),
            config.routing.ipv6,
        )?;
        IpRouteManager::install_rules(&snapshot.plan)?;
        process.start("sing-box", &path)?;
        anyhow::ensure!(
            IpRouteManager::wait_for_interface("chain0", Duration::from_secs(5)),
            "Missing TUN"
        );
        SysctlManager::configure_tun_sysctl("chain0")?;
        IpRouteManager::install_routes(&snapshot.plan)?;
        NftablesManager::apply_ruleset(&NftablesManager::generate_ruleset(&config, &lans)?)?;
        println!("READY");
        std::io::stdout().flush()?;
        let _ = std::io::stdin().lock().lines().next();
        Ok(())
    })();
    NftablesManager::restore(None)?;
    process.stop();
    snapshot.restore()?;
    result
}
