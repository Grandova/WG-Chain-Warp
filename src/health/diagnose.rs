use crate::network::iproute::IpRouteManager;
use crate::network::nftables::NftablesManager;

pub struct SystemDiagnostician;

impl SystemDiagnostician {
    pub fn generate_report() -> String {
        let mut r = String::from("=== SOOYA SYSTEM DIAGNOSTIC REPORT ===\n");
        r.push_str(&format!("OS / Arch : {} / {}\n", std::env::consts::OS, std::env::consts::ARCH));
        r.push_str("Kernel    : Sooya WarpKernel (Native ChaCha20-Poly1305 / Noise_IKpsk2)\n");

        r.push_str("\n[1] Physical Uplink:\n");
        match IpRouteManager::detect_default_uplink() {
            Ok(up) => r.push_str(&format!("  Interface: {} | Gateway: {} | IP: {:?}\n", up.interface, up.gateway, up.local_ip)),
            Err(e) => r.push_str(&format!("  Error: {}\n", e)),
        }

        r.push_str("\n[2] Policy Routing Rules:\n");
        for fam in ["-4", "-6"] {
            if let Ok(rules) = IpRouteManager::run(&[fam, "rule", "show"]) {
                r.push_str(&rules);
            }
        }

        r.push_str("\n[3] Routing Table 2023:\n");
        if let Ok(rt) = IpRouteManager::run(&["route", "show", "table", "2023"]) {
            r.push_str(if rt.trim().is_empty() { "  (empty)\n" } else { &rt });
        }

        r.push_str("\n[4] Nftables Ruleset (inet chainproxy):\n");
        match NftablesManager::list_table_rules() {
            Ok(rules) => r.push_str(&rules),
            Err(_) => r.push_str("  (table inet chainproxy not active)\n"),
        }
        r
    }
}
