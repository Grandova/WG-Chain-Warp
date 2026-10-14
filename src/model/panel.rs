use crate::error::{ChainError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub const DEFAULT_PANEL_PORT: u16 = 54321;
pub const DEFAULT_PANEL_LISTEN: &str = "0.0.0.0";
pub const DEFAULT_PANEL_USER: &str = "admin";
pub const DEFAULT_PANEL_PASS: &str = "admin";
pub const DEFAULT_PANEL_BASE_PATH: &str = "/";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelSetting {
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

fn default_listen() -> String {
    DEFAULT_PANEL_LISTEN.to_string()
}

fn default_port() -> u16 {
    DEFAULT_PANEL_PORT
}

fn default_username() -> String {
    DEFAULT_PANEL_USER.to_string()
}

fn default_password() -> String {
    DEFAULT_PANEL_PASS.to_string()
}

fn default_base_path() -> String {
    DEFAULT_PANEL_BASE_PATH.to_string()
}

fn default_session_secret() -> String {
    Uuid::new_v4().to_string()
}

impl Default for PanelSetting {
    fn default() -> Self {
        Self {
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
    pub fn normalize(&mut self) {
        let trimmed_listen = self.listen.trim();
        if trimmed_listen.is_empty() {
            self.listen = DEFAULT_PANEL_LISTEN.to_string();
        } else {
            self.listen = trimmed_listen.to_string();
        }

        if self.port == 0 {
            self.port = DEFAULT_PANEL_PORT;
        }

        let trimmed_user = self.username.trim();
        if trimmed_user.is_empty() {
            self.username = DEFAULT_PANEL_USER.to_string();
        } else {
            self.username = trimmed_user.to_string();
        }

        if self.password.is_empty() {
            self.password = DEFAULT_PANEL_PASS.to_string();
        }

        let mut bp = self.base_path.trim().to_string();
        if bp.is_empty() {
            bp = "/".to_string();
        } else {
            if !bp.starts_with('/') {
                bp.insert(0, '/');
            }
            if !bp.ends_with('/') {
                bp.push('/');
            }
        }
        self.base_path = bp;

        if self.session_secret.trim().is_empty() {
            self.session_secret = default_session_secret();
        }
    }

    pub fn load_or_default(data_dir: &Path) -> Self {
        let file = data_dir.join("panel.json");
        if file.exists() {
            if let Ok(content) = fs::read_to_string(&file) {
                if let Ok(mut setting) = serde_json::from_str::<PanelSetting>(&content) {
                    setting.normalize();
                    return setting;
                }
            }
        }
        let mut def = Self::default();
        def.normalize();
        let _ = def.save(data_dir);
        def
    }

    pub fn save(&mut self, data_dir: &Path) -> Result<()> {
        self.normalize();
        fs::create_dir_all(data_dir)?;
        let file = data_dir.join("panel.json");
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&file, content)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&file, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn bind_addr(&self) -> String {
        let host = if self.listen.trim().is_empty() {
            "0.0.0.0"
        } else {
            self.listen.trim()
        };
        format!("{}:{}", host, self.port)
    }

    pub fn verify_credentials(&self, user: &str, pass: &str) -> bool {
        self.username == user && self.password == pass
    }

    pub fn rotate_session_secret(&mut self) {
        self.session_secret = Uuid::new_v4().to_string();
    }

    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(ChainError::ValidationError(
                "面板端口必须在 1 ~ 65535 之间".to_string(),
            ));
        }
        if !self.listen.trim().is_empty() && self.listen.trim() != "0.0.0.0" && self.listen.trim() != "::" {
            if self.listen.trim().parse::<std::net::IpAddr>().is_err() {
                return Err(ChainError::ValidationError(format!(
                    "无效的面板监听 IP 地址: {}",
                    self.listen
                )));
            }
        }
        if self.username.trim().is_empty() {
            return Err(ChainError::ValidationError(
                "面板用户名不能为空".to_string(),
            ));
        }
        if self.password.is_empty() {
            return Err(ChainError::ValidationError(
                "面板密码不能为空".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panel_setting_normalize_and_save() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = PanelSetting {
            listen: "".to_string(),
            port: 54321,
            username: "admin".to_string(),
            password: "secret".to_string(),
            base_path: "xui".to_string(),
            session_secret: "".to_string(),
        };
        s.save(dir.path()).unwrap();
        assert_eq!(s.listen, "0.0.0.0");
        assert_eq!(s.base_path, "/xui/");
        assert!(!s.session_secret.is_empty());

        let loaded = PanelSetting::load_or_default(dir.path());
        assert_eq!(loaded.port, 54321);
        assert_eq!(loaded.base_path, "/xui/");
        assert!(loaded.verify_credentials("admin", "secret"));
        assert!(!loaded.verify_credentials("admin", "wrong"));
    }
}
