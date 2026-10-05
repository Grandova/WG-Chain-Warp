use crate::error::{ChainError, Result};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct SingBoxVersionInfo {
    pub version: String,
    pub has_wireguard: bool,
    pub has_tun: bool,
    pub is_supported: bool,
}

pub struct SingBoxManager {
    child: Option<Child>,
    is_running: Arc<AtomicBool>,
}

impl SingBoxManager {
    pub fn new() -> Self {
        Self {
            child: None,
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Automatically resolve an available sing-box binary path across system locations
    pub fn resolve_binary(hint: &str) -> Result<String> {
        let mut candidates = Vec::new();
        let trimmed = hint.trim();
        if !trimmed.is_empty() {
            candidates.push(trimmed.to_string());
        }
        candidates.push("/usr/local/bin/sing-box".to_string());
        candidates.push("/usr/bin/sing-box".to_string());
        candidates.push("/bin/sing-box".to_string());
        candidates.push("/var/lib/chainproxy/sing-box".to_string());
        candidates.push("sing-box".to_string());

        for c in &candidates {
            if let Ok(out) = Command::new(c).arg("version").output() {
                if out.status.success() {
                    return Ok(c.clone());
                }
            }
        }

        Err(ChainError::SingBoxError(
            "未在系统上检测到 sing-box 代理引擎！\n请执行以下命令一键安装官方 sing-box:\n  curl -fsSL https://sing-box.app/install.sh | sudo bash\n安装完成后重新执行 [5] 即可启动链路。".to_string(),
        ))
    }

    /// Check sing-box version and feature support
    pub fn probe_version(singbox_bin: &str) -> Result<SingBoxVersionInfo> {
        let bin = Self::resolve_binary(singbox_bin)?;
        let output = Command::new(&bin)
            .arg("version")
            .output()
            .map_err(|e| ChainError::SingBoxError(format!("Failed to execute '{}': {}", bin, e)))?;

        if !output.status.success() {
            return Err(ChainError::SingBoxError(format!(
                "'{} version' returned exit code {}",
                bin,
                output.status.code().unwrap_or(-1)
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let first_line = stdout.lines().next().unwrap_or("").to_string();

        let has_wireguard =
            stdout.contains("with_wireguard") || !stdout.contains("without_wireguard");
        let has_tun = stdout.contains("with_gvisor")
            || stdout.contains("tun")
            || !stdout.contains("without_tun");

        // Parse version tag (e.g. "sing-box version 1.11.0", "1.12.0", etc.)
        let is_supported = stdout.contains("1.11")
            || stdout.contains("1.12")
            || stdout.contains("1.13")
            || stdout.contains("1.14")
            || stdout.contains("1.15")
            || stdout.contains("1.16")
            || stdout.contains("1.17")
            || stdout.contains("1.18")
            || stdout.contains("1.19")
            || stdout.contains("1.20");

        Ok(SingBoxVersionInfo {
            version: first_line,
            has_wireguard,
            has_tun,
            is_supported,
        })
    }

    /// Validate configuration file using sing-box check -c <file>
    pub fn check_config(singbox_bin: &str, config_path: &Path) -> Result<()> {
        let bin = Self::resolve_binary(singbox_bin)?;
        let output = Command::new(&bin)
            .arg("check")
            .arg("-c")
            .arg(config_path)
            .output()
            .map_err(|e| {
                ChainError::SingBoxError(format!("Failed to execute '{} check': {}", bin, e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(ChainError::SingBoxError(format!(
                "sing-box config validation failed:\n{}{}",
                stdout, stderr
            )));
        }

        Ok(())
    }

    /// Start sing-box with specified configuration
    pub fn start(&mut self, singbox_bin: &str, config_path: &Path) -> Result<()> {
        self.stop();

        let bin = Self::resolve_binary(singbox_bin)?;

        let log_path = config_path
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join("singbox.log");

        info!(
            "Starting sing-box process with binary '{}' and config {:?}, logging to {:?}",
            bin, config_path, log_path
        );
        let mut command = Command::new(&bin);
        command
            .arg("run")
            .arg("-c")
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            // Let sing-tun release its routes if the owning daemon dies unexpectedly.
            let parent = std::process::id() as libc::pid_t;
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != parent {
                        libc::raise(libc::SIGTERM);
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn().map_err(|e| {
            ChainError::SingBoxError(format!("Failed to spawn sing-box ('{}'): {}", bin, e))
        })?;

        // Background threads: stream sing-box output to tracing (for journalctl -f) and singbox.log file
        if let Some(stdout) = child.stdout.take() {
            let log_path_clone = log_path.clone();
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader, Write};
                let reader = BufReader::new(stdout);
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&log_path_clone)
                    .ok();
                for line in reader.lines().map_while(std::result::Result::ok) {
                    tracing::info!(target: "singbox", "{}", line);
                    if let Some(ref mut f) = file {
                        let _ = writeln!(f, "{}", line);
                        let _ = f.flush();
                    }
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let log_path_clone = log_path.clone();
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader, Write};
                let reader = BufReader::new(stderr);
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .append(true)
                    .open(&log_path_clone)
                    .ok();
                for line in reader.lines().map_while(std::result::Result::ok) {
                    tracing::warn!(target: "singbox", "{}", line);
                    if let Some(ref mut f) = file {
                        let _ = writeln!(f, "{}", line);
                        let _ = f.flush();
                    }
                }
            });
        }

        // Sleep briefly to ensure it doesn't immediately crash on invalid config/permission
        std::thread::sleep(Duration::from_millis(800));
        match child.try_wait() {
            Ok(Some(status)) => {
                self.is_running.store(false, Ordering::SeqCst);
                let logs = std::fs::read_to_string(&log_path).unwrap_or_default();
                let trimmed = logs.trim();
                let msg = if trimmed.is_empty() {
                    format!("sing-box 启动后立即异常退出 (状态码: {})", status)
                } else {
                    format!(
                        "sing-box 启动后立即异常退出 (状态码: {}):\n{}",
                        status, trimmed
                    )
                };
                tracing::error!("{}", msg);
                return Err(ChainError::SingBoxError(msg));
            }
            Ok(None) => {
                info!("sing-box 进程启动成功 (PID {})", child.id());
                self.child = Some(child);
                self.is_running.store(true, Ordering::SeqCst);
            }
            Err(e) => {
                warn!("Error waiting on sing-box child status: {}", e);
                self.child = Some(child);
                self.is_running.store(true, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    /// Stop running sing-box process
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            info!("Stopping sing-box child process PID {}", child.id());
            #[cfg(target_os = "linux")]
            {
                // SIGKILL skips sing-tun's own IPv6 route/rule cleanup.
                let _ = Command::new("kill")
                    .args(["-TERM", &child.id().to_string()])
                    .output();
                for _ in 0..30 {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        self.is_running.store(false, Ordering::SeqCst);
    }

    pub fn is_running(&mut self) -> bool {
        let running = self
            .child
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(None)));
        self.is_running.store(running, Ordering::SeqCst);
        running
    }
}

impl Drop for SingBoxManager {
    fn drop(&mut self) {
        self.stop();
    }
}
