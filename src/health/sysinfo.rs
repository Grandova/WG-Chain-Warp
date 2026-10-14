use crate::singbox::process::SingBoxManager;
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
    cached_sb_version: Option<String>,
}

pub struct SysInfoCollector {
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
            prev: Mutex::new(PrevSample {
                cpu_total,
                cpu_idle,
                net_sent,
                net_recv,
                last_time: Instant::now(),
                cached_sb_version: None,
            }),
        }
    }

    pub fn collect(&self, singbox_bin: &str) -> ServerSystemStatus {
        let mut guard = self.prev.lock().unwrap();
        let now = Instant::now();
        let elapsed_secs = now.duration_since(guard.last_time).as_secs_f64();

        // 1. CPU %
        let (cur_total, cur_idle) = Self::read_cpu_jiffies().unwrap_or((guard.cpu_total, guard.cpu_idle));
        let total_diff = cur_total.saturating_sub(guard.cpu_total);
        let idle_diff = cur_idle.saturating_sub(guard.cpu_idle);
        let cpu = if total_diff > 0 {
            let used = total_diff.saturating_sub(idle_diff) as f64;
            ((used / total_diff as f64) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };

        // 2. Network IO & Traffic
        let (cur_recv, cur_sent) = Self::read_net_bytes().unwrap_or((guard.net_recv, guard.net_sent));
        let (up_speed, down_speed) = if elapsed_secs >= 0.2 && (guard.net_sent > 0 || guard.net_recv > 0) {
            let sent_diff = cur_sent.saturating_sub(guard.net_sent) as f64;
            let recv_diff = cur_recv.saturating_sub(guard.net_recv) as f64;
            ((sent_diff / elapsed_secs) as u64, (recv_diff / elapsed_secs) as u64)
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

        let sb_ver = if let Some(ref v) = guard.cached_sb_version {
            v.clone()
        } else {
            let v = SingBoxManager::probe_version(singbox_bin)
                .map(|info| info.version)
                .unwrap_or_else(|_| "未安装".to_string());
            guard.cached_sb_version = Some(v.clone());
            v
        };
        drop(guard);

        let cpu_cores = Self::read_cpu_cores();
        let (mem, swap) = Self::read_mem_and_swap();
        let disk = Self::read_disk_usage();
        let uptime = Self::read_uptime();
        let loads = Self::read_loadavg();
        let tcp_count = Self::count_proc_net_lines(&["/proc/net/tcp", "/proc/net/tcp6"]);
        let udp_count = Self::count_proc_net_lines(&["/proc/net/udp", "/proc/net/udp6"]);

        ServerSystemStatus {
            cpu,
            cpu_cores,
            mem,
            swap,
            disk,
            uptime,
            loads,
            tcp_count,
            udp_count,
            net_io: NetIoStats {
                up: up_speed,
                down: down_speed,
            },
            net_traffic: NetTrafficStats {
                sent: cur_sent,
                recv: cur_recv,
            },
            singbox_version: sb_ver,
            chainproxy_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn read_cpu_jiffies() -> Option<(u64, u64)> {
        let content = fs::read_to_string("/proc/stat").ok()?;
        let first_line = content.lines().find(|l| l.starts_with("cpu "))?;
        let parts: Vec<u64> = first_line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse::<u64>().ok())
            .collect();
        if parts.len() < 4 {
            return None;
        }
        let total: u64 = parts.iter().sum();
        // idle is index 3, iowait is index 4
        let idle = parts[3] + parts.get(4).copied().unwrap_or(0);
        Some((total, idle))
    }

    fn read_cpu_cores() -> usize {
        if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
            let count = content
                .lines()
                .filter(|l| l.starts_with("processor"))
                .count();
            if count > 0 {
                return count;
            }
        }
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }

    fn read_mem_and_swap() -> (UsagePair, UsagePair) {
        let mut mem_total_kb = 0u64;
        let mut mem_avail_kb = 0u64;
        let mut swap_total_kb = 0u64;
        let mut swap_free_kb = 0u64;

        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                let mut parts = line.split_whitespace();
                let key = parts.next().unwrap_or("");
                let val = parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
                match key {
                    "MemTotal:" => mem_total_kb = val,
                    "MemAvailable:" => mem_avail_kb = val,
                    "SwapTotal:" => swap_total_kb = val,
                    "SwapFree:" => swap_free_kb = val,
                    _ => {}
                }
            }
        }

        let mem_total = mem_total_kb * 1024;
        let mem_used = mem_total_kb.saturating_sub(mem_avail_kb) * 1024;
        let swap_total = swap_total_kb * 1024;
        let swap_used = swap_total_kb.saturating_sub(swap_free_kb) * 1024;

        (
            UsagePair {
                current: mem_used,
                total: mem_total,
            },
            UsagePair {
                current: swap_used,
                total: swap_total,
            },
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
                        let block_size = stat.f_frsize as u64;
                        let total = (stat.f_blocks as u64).saturating_mul(block_size);
                        let avail = (stat.f_bavail as u64).saturating_mul(block_size);
                        let used = total.saturating_sub(avail);
                        return UsagePair {
                            current: used,
                            total,
                        };
                    }
                }
            }
        }
        UsagePair { current: 0, total: 0 }
    }

    fn read_uptime() -> u64 {
        if let Ok(content) = fs::read_to_string("/proc/uptime") {
            if let Some(first) = content.split_whitespace().next() {
                if let Ok(secs) = first.parse::<f64>() {
                    return secs as u64;
                }
            }
        }
        0
    }

    fn read_loadavg() -> [f64; 3] {
        if let Ok(content) = fs::read_to_string("/proc/loadavg") {
            let parts: Vec<f64> = content
                .split_whitespace()
                .take(3)
                .filter_map(|s| s.parse::<f64>().ok())
                .collect();
            if parts.len() == 3 {
                return [parts[0], parts[1], parts[2]];
            }
        }
        [0.0, 0.0, 0.0]
    }

    fn count_proc_net_lines(paths: &[&str]) -> usize {
        let mut total = 0usize;
        for p in paths {
            if let Ok(content) = fs::read_to_string(p) {
                let count = content.lines().count();
                if count > 1 {
                    total += count - 1;
                }
            }
        }
        total
    }

    fn read_net_bytes() -> Option<(u64, u64)> {
        let content = fs::read_to_string("/proc/net/dev").ok()?;
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;

        for line in content.lines().skip(2) {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            let iface = parts[0].trim();
            // Skip loopback and internal virtual tun interfaces to avoid double counting
            if iface == "lo" || iface == "chain0" || iface.starts_with("veth") || iface.starts_with("docker") {
                continue;
            }
            let nums: Vec<u64> = parts[1]
                .split_whitespace()
                .filter_map(|s| s.parse::<u64>().ok())
                .collect();
            if nums.len() >= 9 {
                total_rx = total_rx.saturating_add(nums[0]);
                total_tx = total_tx.saturating_add(nums[8]);
            }
        }

        Some((total_rx, total_tx))
    }
}
