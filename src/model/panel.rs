use crate::error::{ChainError, Result};
use crate::web::SESSION_COOKIE_NAME;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;

pub const DEFAULT_PANEL_PORT: u16 = 54321;
pub const DEFAULT_PANEL_LISTEN: &str = "0.0.0.0";
pub const DEFAULT_PANEL_USER: &str = "admin";
pub const DEFAULT_PANEL_PASS: &str = "admin";
pub const DEFAULT_PANEL_BASE_PATH: &str = "/";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelSetting {
    #[serde(default = "default_instance_id")]
    pub instance_id: String,
    #[serde(default)]
    pub host_fingerprint: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_username")]
    pub username: String,
    #[serde(default = "default_password")]
    pub password: String,
    #[serde(default = "default_base_path")]
    pub base_path: String,
    #[serde(default = "default_session_secret")]
    pub session_secret: String,
}

fn default_instance_id() -> String {
    format!("{:012x}", rand::thread_rng().gen::<u64>() & 0xffff_ffff_ffff)
}
fn default_listen() -> String { DEFAULT_PANEL_LISTEN.to_string() }
fn default_port() -> u16 { DEFAULT_PANEL_PORT }
fn default_username() -> String { DEFAULT_PANEL_USER.to_string() }
fn default_password() -> String { DEFAULT_PANEL_PASS.to_string() }
fn default_base_path() -> String { DEFAULT_PANEL_BASE_PATH.to_string() }
fn default_session_secret() -> String { format!("{:032x}", rand::thread_rng().gen::<u128>()) }

impl Default for PanelSetting {
    fn default() -> Self {
        Self {
            instance_id: default_instance_id(),
            host_fingerprint: String::new(),
            listen: default_listen(),
            port: default_port(),
            username: default_username(),
            password: default_password(),
            base_path: default_base_path(),
            session_secret: default_session_secret(),
        }
    }
}

impl PanelSetting {
    pub fn compute_host_fingerprint(data_dir: &Path) -> String {
        let machine_id = fs::read_to_string("/etc/machine-id")
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let hostname = fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let dir_str = data_dir.to_string_lossy();
        format!("{}|{}|{}", machine_id, hostname, dir_str)
    }

    pub fn cookie_name(&self) -> String {
        let id: String = self
            .instance_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        if id.is_empty() {
            SESSION_COOKIE_NAME.to_string()
        } else {
            format!("{}_{}", SESSION_COOKIE_NAME, id)
        }
    }

    pub fn normalize(&mut self) {
        let clean_id: String = self
            .instance_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        self.instance_id = if clean_id.is_empty() {
            default_instance_id()
        } else {
            clean_id
        };
        self.listen = if self.listen.trim().is_empty() {
            DEFAULT_PANEL_LISTEN.to_string()
        } else {
            self.listen.trim().to_string()
        };
        if self.port == 0 {
            self.port = DEFAULT_PANEL_PORT;
        }
        self.username = if self.username.trim().is_empty() {
            DEFAULT_PANEL_USER.to_string()
        } else {
            self.username.trim().to_string()
        };
        if self.password.is_empty() {
            self.password = DEFAULT_PANEL_PASS.to_string();
        }
        let mut bp = self.base_path.trim().to_string();
        if bp.is_empty() {
            bp = "/".to_string();
        } else {
            if !bp.starts_with('/') { bp.insert(0, '/'); }
            if !bp.ends_with('/') { bp.push('/'); }
        }
        self.base_path = bp;
        if self.session_secret.trim().is_empty() {
            self.session_secret = default_session_secret();
        }
    }

    pub fn load_or_default(data_dir: &Path) -> Self {
        let file = data_dir.join("panel.json");
        let current_fp = Self::compute_host_fingerprint(data_dir);
        if let Ok(content) = fs::read_to_string(&file) {
            let had_instance_id = content.contains("\"instance_id\"");
            if let Ok(mut setting) = serde_json::from_str::<PanelSetting>(&content) {
                let mut needs_save = !had_instance_id;
                // If container/directory was cloned from another container, isolate session identity
                if !setting.host_fingerprint.is_empty() && setting.host_fingerprint != current_fp {
                    setting.instance_id = default_instance_id();
                    setting.rotate_session_secret();
                    setting.host_fingerprint = current_fp;
                    needs_save = true;
                } else if setting.host_fingerprint.is_empty() {
                    setting.host_fingerprint = current_fp;
                    needs_save = true;
                }
                setting.normalize();
                if needs_save {
                    let _ = setting.save(data_dir);
                }
                return setting;
            }
        }
        let mut def = Self::default();
        def.host_fingerprint = current_fp;
        def.normalize();
        let _ = def.save(data_dir);
        def
    }

    pub fn save(&mut self, data_dir: &Path) -> Result<()> {
        if self.host_fingerprint.is_empty() {
            self.host_fingerprint = Self::compute_host_fingerprint(data_dir);
        }
        self.normalize();
        fs::create_dir_all(data_dir)?;
        let file = data_dir.join("panel.json");
        let mut tmp = tempfile::NamedTempFile::new_in(data_dir)?;
        tmp.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        tmp.persist(&file).map_err(|e| e.error)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&file, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn bind_addr(&self) -> String {
        let host = if self.listen.trim().is_empty() { "0.0.0.0" } else { self.listen.trim() };
        format!("{}:{}", host, self.port)
    }

    pub fn verify_credentials(&self, user: &str, pass: &str) -> bool {
        self.username == user && self.password == pass
    }

    pub fn rotate_session_secret(&mut self) {
        self.session_secret = default_session_secret();
    }

    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(ChainError::ValidationError("面板端口必须在 1 ~ 65535 之间".to_string()));
        }
        let l = self.listen.trim();
        if !l.is_empty() && l != "0.0.0.0" && l != "::" && l.parse::<std::net::IpAddr>().is_err() {
            return Err(ChainError::ValidationError(format!("无效的面板监听 IP 地址: {}", self.listen)));
        }
        if self.username.trim().is_empty() || self.password.is_empty() {
            return Err(ChainError::ValidationError("面板用户名和密码不能为空".to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panel_setting_legacy_upgrade_and_restart_stability() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_json = r#"{
            "listen": "0.0.0.0",
            "port": 5000,
            "username": "custom_admin",
            "password": "custom_password",
            "base_path": "/panel/",
            "session_secret": "legacysecret1234567890abcdef"
        }"#;
        fs::write(dir.path().join("panel.json"), legacy_json).unwrap();

        // Upgrade from legacy panel.json without instance_id
        let upgraded = PanelSetting::load_or_default(dir.path());
        assert_eq!(upgraded.port, 5000);
        assert_eq!(upgraded.username, "custom_admin");
        assert_eq!(upgraded.password, "custom_password");
        assert_eq!(upgraded.base_path, "/panel/");
        assert_eq!(upgraded.session_secret, "legacysecret1234567890abcdef");
        assert!(!upgraded.instance_id.is_empty());
        assert_eq!(upgraded.cookie_name(), format!("sooya_session_{}", upgraded.instance_id));

        // Restarting must keep the exact same instance_id and cookie_name
        let restarted = PanelSetting::load_or_default(dir.path());
        assert_eq!(restarted.instance_id, upgraded.instance_id);
        assert_eq!(restarted.cookie_name(), upgraded.cookie_name());
        assert_eq!(restarted.session_secret, upgraded.session_secret);
    }

    #[test]
    fn test_panel_setting_cloned_container_rotates_identity() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let panel_a = PanelSetting::load_or_default(dir_a.path());
        // Simulate cloning container A's panel.json into container B
        fs::copy(dir_a.path().join("panel.json"), dir_b.path().join("panel.json")).unwrap();

        let panel_b = PanelSetting::load_or_default(dir_b.path());
        assert_ne!(panel_a.instance_id, panel_b.instance_id);
        assert_ne!(panel_a.cookie_name(), panel_b.cookie_name());
        assert_ne!(panel_a.session_secret, panel_b.session_secret);
        assert_eq!(panel_a.port, panel_b.port);
        assert_eq!(panel_a.username, panel_b.username);
    }
}

