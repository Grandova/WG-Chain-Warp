use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsagePair {
    pub current: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetIoStats {
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetTrafficStats {
    pub sent: u64,
    pub recv: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSystemStatus {
    pub cpu: f64,
    pub cpu_cores: usize,
    pub mem: UsagePair,
    pub swap: UsagePair,
    pub disk: UsagePair,
    pub uptime: u64,
    pub loads: [f64; 3],
    pub tcp_count: usize,
    pub udp_count: usize,
    pub net_io: NetIoStats,
    pub net_traffic: NetTrafficStats,
    pub singbox_version: String,
    pub chainproxy_version: String,
}

struct PrevSample {
    cpu_total: u64,
    cpu_idle: u64,
    net_sent: u64,
    net_recv: u64,
    last_time: Instant,
}

pub struct SysInfoCollector {
    cpu_cores: usize,
    prev: Mutex<PrevSample>,
}

impl Default for SysInfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SysInfoCollector {
    pub fn new() -> Self {
        let (cpu_total, cpu_idle) = Self::read_cpu_jiffies().unwrap_or((0, 0));
        let (net_recv, net_sent) = Self::read_net_bytes().unwrap_or((0, 0));
        Self {
            cpu_cores: Self::read_cpu_cores(),
            prev: Mutex::new(PrevSample {
                cpu_total,
                cpu_idle,
                net_sent,
                net_recv,
                last_time: Instant::now(),
            }),
        }
    }

    pub fn collect(&self) -> ServerSystemStatus {
        let mut guard = self.prev.lock().unwrap();
        let now = Instant::now();
        let elapsed_secs = now.duration_since(guard.last_time).as_secs_f64();

        let (cur_total, cur_idle) = Self::read_cpu_jiffies().unwrap_or((guard.cpu_total, guard.cpu_idle));
        let total_diff = cur_total.saturating_sub(guard.cpu_total);
        let idle_diff = cur_idle.saturating_sub(guard.cpu_idle);
        let cpu = if total_diff > 0 {
            (((total_diff.saturating_sub(idle_diff) as f64) / total_diff as f64) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };

        let (cur_recv, cur_sent) = Self::read_net_bytes().unwrap_or((guard.net_recv, guard.net_sent));
        let (up_speed, down_speed) = if elapsed_secs >= 0.2 && (guard.net_sent > 0 || guard.net_recv > 0) {
            (
                (cur_sent.saturating_sub(guard.net_sent) as f64 / elapsed_secs) as u64,
                (cur_recv.saturating_sub(guard.net_recv) as f64 / elapsed_secs) as u64,
            )
        } else {
            (0, 0)
        };

        if elapsed_secs >= 0.2 {
            guard.cpu_total = cur_total;
            guard.cpu_idle = cur_idle;
            guard.net_sent = cur_sent;
            guard.net_recv = cur_recv;
            guard.last_time = now;
        }
        drop(guard);

        let (mem, swap) = Self::read_mem_and_swap();
        let (tcp_count, udp_count) = Self::read_socket_counts();

        ServerSystemStatus {
            cpu,
            cpu_cores: self.cpu_cores,
            mem,
            swap,
            disk: Self::read_disk_usage(),
            uptime: Self::read_uptime(),
            loads: Self::read_loadavg(),
            tcp_count,
            udp_count,
            net_io: NetIoStats { up: up_speed, down: down_speed },
            net_traffic: NetTrafficStats { sent: cur_sent, recv: cur_recv },
            singbox_version: "Sooya WarpKernel (Rust Native)".to_string(),
            chainproxy_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn read_cpu_jiffies() -> Option<(u64, u64)> {
        let content = fs::read_to_string("/proc/stat").ok()?;
        let first = content.lines().find(|l| l.starts_with("cpu "))?;
        let (mut total, mut idle, mut count) = (0u64, 0u64, 0usize);
        for (idx, token) in first.split_whitespace().skip(1).enumerate() {
            if let Ok(v) = token.parse::<u64>() {
                total = total.saturating_add(v);
                if idx == 3 || idx == 4 { idle = idle.saturating_add(v); }
                count += 1;
            }
        }
        (count >= 4).then_some((total, idle))
    }

    fn read_cpu_cores() -> usize {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    }

    fn read_mem_and_swap() -> (UsagePair, UsagePair) {
        let (mut mt, mut ma, mut st, mut sf) = (0u64, 0u64, 0u64, 0u64);
        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                let mut parts = line.split_whitespace();
                let key = parts.next().unwrap_or("");
                let mut val = || parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
                match key {
                    "MemTotal:" => mt = val(),
                    "MemAvailable:" => ma = val(),
                    "SwapTotal:" => st = val(),
                    "SwapFree:" => sf = val(),
                    _ => {}
                }
            }
        }
        (
            UsagePair { current: mt.saturating_sub(ma) * 1024, total: mt * 1024 },
            UsagePair { current: st.saturating_sub(sf) * 1024, total: st * 1024 },
        )
    }

    fn read_disk_usage() -> UsagePair {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            if let Ok(path) = CString::new("/") {
                unsafe {
                    let mut stat: libc::statvfs = std::mem::zeroed();
                    if libc::statvfs(path.as_ptr(), &mut stat) == 0 {
                        let bsize = stat.f_frsize as u64;
                        let total = (stat.f_blocks as u64).saturating_mul(bsize);
                        let avail = (stat.f_bavail as u64).saturating_mul(bsize);
                        return UsagePair { current: total.saturating_sub(avail), total };
                    }
                }
            }
        }
        UsagePair::default()
    }

    fn read_uptime() -> u64 {
        fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|c| c.split_whitespace().next()?.parse::<f64>().ok())
            .map(|s| s as u64)
            .unwrap_or(0)
    }

    fn read_loadavg() -> [f64; 3] {
        let mut out = [0.0; 3];
        if let Ok(c) = fs::read_to_string("/proc/loadavg") {
            for (i, t) in c.split_whitespace().take(3).enumerate() {
                out[i] = t.parse().unwrap_or(0.0);
            }
        }
        out
    }

    fn read_socket_counts() -> (usize, usize) {
        let (mut tcp, mut udp) = (0usize, 0usize);
        for path in ["/proc/net/sockstat", "/proc/net/sockstat6"] {
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines() {
                    let mut parts = line.split_whitespace();
                    let proto = parts.next().unwrap_or("");
                    if (proto == "TCP:" || proto == "TCP6:") && parts.next() == Some("inuse") {
                        tcp += parts.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                    } else if (proto == "UDP:" || proto == "UDP6:") && parts.next() == Some("inuse") {
                        udp += parts.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                    }
                }
            }
        }
        (tcp, udp)
    }

    fn read_net_bytes() -> Option<(u64, u64)> {
        let content = fs::read_to_string("/proc/net/dev").ok()?;
        let (mut rx_tot, mut tx_tot) = (0u64, 0u64);
        for line in content.lines().skip(2) {
            let Some((iface_raw, stats_raw)) = line.split_once(':') else { continue };
            let iface = iface_raw.trim();
            if iface == "lo" || iface == "chain0" || iface.starts_with("veth") || iface.starts_with("docker") {
                continue;
            }
            let mut cols = stats_raw.split_whitespace();
            let Some(rx) = cols.next().and_then(|s| s.parse::<u64>().ok()) else { continue };
            let Some(tx) = cols.nth(7).and_then(|s| s.parse::<u64>().ok()) else { continue };
            rx_tot = rx_tot.saturating_add(rx);
            tx_tot = tx_tot.saturating_add(tx);
        }
        Some((rx_tot, tx_tot))
    }
}
