use crate::error::{ChainError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Socks5Config {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5User {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5ServerConfig {
    pub listen: std::net::IpAddr,
    pub port: u16,
    pub users: Vec<Socks5User>,
}

impl Socks5ServerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 || self.users.is_empty() {
            return Err(ChainError::ValidationError(
                "SOCKS5 服务端必须配置有效端口和至少一个用户".to_string(),
            ));
        }
        let mut names = std::collections::HashSet::new();
        for user in &self.users {
            if !(1..=255).contains(&user.username.len())
                || !(1..=255).contains(&user.password.len())
            {
                return Err(ChainError::ValidationError(
                    "SOCKS5 用户名、密码必须为 1–255 字节".to_string(),
                ));
            }
            if !names.insert(&user.username) {
                return Err(ChainError::ValidationError(
                    "SOCKS5 用户名不能重复".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl Socks5Config {
    /// Parse Socks5 proxy configuration from various common formats:
    /// - `user:password@host:port` (standard with auth)
    /// - `socks5://user:password@host:port`
    /// - `host:port:user:password` (common residential proxy export)
    /// - `host:port@user:password`
    /// - `host:port` or `socks5://host:port` (no auth)
    /// - JSON formatted string
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ChainError::ValidationError("Socks5 代理配置不能为空".to_string()));
        }

        // 1. Try parsing JSON format
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            if let Ok(cfg) = serde_json::from_str::<Socks5Config>(trimmed) {
                if !cfg.server.is_empty() && cfg.port > 0 {
                    return Ok(cfg);
                }
            }
        }

        // 2. Strip standard URL prefixes
        let clean = trimmed
            .strip_prefix("socks5://")
            .or_else(|| trimmed.strip_prefix("socks5h://"))
            .or_else(|| trimmed.strip_prefix("socks://"))
            .unwrap_or(trimmed)
            .trim();

        // 3. Format: user:password@host:port (or host:port@user:password)
        if let Some(at_idx) = clean.rfind('@') {
            let (left, right) = clean.split_at(at_idx);
            let right = &right[1..]; // skip '@'

            // Case A: user:password@host:port
            if let Ok((host, port)) = parse_host_port(right) {
                let (user, pass) = parse_user_pass(left);
                return Ok(Socks5Config {
                    server: host,
                    port,
                    username: user,
                    password: pass,
                });
            }

            // Case B: host:port@user:password
            if let Ok((host, port)) = parse_host_port(left) {
                let (user, pass) = parse_user_pass(right);
                return Ok(Socks5Config {
                    server: host,
                    port,
                    username: user,
                    password: pass,
                });
            }
        }

        // 4. Format: host:port:user:password (frequently used by proxy vendors)
        let colon_parts: Vec<&str> = clean.split(':').collect();
        if colon_parts.len() >= 4 {
            if let Ok(port) = colon_parts[1].parse::<u16>() {
                if port > 0 {
                    let host = colon_parts[0].trim().to_string();
                    let user = colon_parts[2].trim().to_string();
                    let pass = colon_parts[3..].join(":");
                    return Ok(Socks5Config {
                        server: host,
                        port,
                        username: Some(user).filter(|u| !u.is_empty()),
                        password: Some(pass).filter(|p| !p.is_empty()),
                    });
                }
            }
        }

        // 5. Format: host:port (without authentication)
        if let Ok((host, port)) = parse_host_port(clean) {
            return Ok(Socks5Config {
                server: host,
                port,
                username: None,
                password: None,
            });
        }

        Err(ChainError::ValidationError(format!(
            "无法识别的 Socks5 代理格式: '{}'。支持格式如: user:pass@host:port 或 host:port:user:pass 或 socks5://user:pass@host:port",
            clean
        )))
    }

    /// Redacted string safe for UI display and logs (masks password)
    pub fn redacted_string(&self) -> String {
        match (&self.username, &self.password) {
            (Some(u), Some(_)) => format!("socks5://{}:********@{}:{}", u, self.server, self.port),
            (Some(u), None) => format!("socks5://{}@{}:{}", u, self.server, self.port),
            (None, _) => format!("socks5://{}:{}", self.server, self.port),
        }
    }

    /// Full URL including raw credentials
    pub fn to_url(&self) -> String {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("socks5://{}:{}@{}:{}", u, p, self.server, self.port),
            (Some(u), None) => format!("socks5://{}@{}:{}", u, self.server, self.port),
            (None, _) => format!("socks5://{}:{}", self.server, self.port),
        }
    }
}

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ChainError::ValidationError("主机与端口不能为空".to_string()));
    }

    // IPv6 literal check, e.g. [2001:db8::1]:1080
    if s.starts_with('[') {
        if let Some(close_bracket) = s.find(']') {
            let host = &s[1..close_bracket];
            let rest = &s[close_bracket + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|_| ChainError::ValidationError("IPv6 端口格式无效".to_string()))?;
                if port > 0 {
                    return Ok((host.to_string(), port));
                }
            }
        }
    }

    if let Some(colon_idx) = s.rfind(':') {
        let (host, port_part) = s.split_at(colon_idx);
        let port_str = &port_part[1..];
        if let Ok(port) = port_str.parse::<u16>() {
            let host = host.trim().to_string();
            if !host.is_empty() && port > 0 {
                return Ok((host, port));
            }
        }
    }

    Err(ChainError::ValidationError(format!("无效的主机与端口格式: '{}'", s)))
}

fn parse_user_pass(s: &str) -> (Option<String>, Option<String>) {
    let s = s.trim();
    if s.is_empty() {
        return (None, None);
    }
    if let Some(colon_idx) = s.find(':') {
        let (user, pass_part) = s.split_at(colon_idx);
        let pass = &pass_part[1..];
        (
            Some(user.trim().to_string()).filter(|u| !u.is_empty()),
            Some(pass.to_string()).filter(|p| !p.is_empty()),
        )
    } else {
        (Some(s.trim().to_string()), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_requires_valid_unique_credentials() {
        let mut server = Socks5ServerConfig {
            listen: "0.0.0.0".parse().unwrap(),
            port: 1080,
            users: vec![],
        };
        assert!(server.validate().is_err());
        server.users.push(Socks5User {
            username: "alice".to_string(),
            password: "p".repeat(255),
        });
        assert!(server.validate().is_ok());
        server.users[0].password.push('p');
        assert!(server.validate().is_err());
        server.users[0].password = "secret".to_string();
        server.users.push(server.users[0].clone());
        assert!(server.validate().is_err());
        server.users[1].username = "bob".to_string();
        assert!(server.validate().is_ok());
        server.port = 0;
        assert!(server.validate().is_err());
    }

    #[test]
    fn test_parse_standard_at_format() {
        let input = "demo_user:p@ss;word;;;@proxy.example.com:9000";
        let cfg = Socks5Config::parse(input).unwrap();
        assert_eq!(cfg.server, "proxy.example.com");
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.username.as_deref(), Some("demo_user"));
        assert_eq!(cfg.password.as_deref(), Some("p@ss;word;;;"));
        assert_eq!(
            cfg.redacted_string(),
            "socks5://demo_user:********@proxy.example.com:9000"
        );
    }

    #[test]
    fn test_parse_socks5_scheme_prefix() {
        let input = "socks5://myuser:secret123@192.0.2.1:1080";
        let cfg = Socks5Config::parse(input).unwrap();
        assert_eq!(cfg.server, "192.0.2.1");
        assert_eq!(cfg.port, 1080);
        assert_eq!(cfg.username.as_deref(), Some("myuser"));
        assert_eq!(cfg.password.as_deref(), Some("secret123"));
    }

    #[test]
    fn test_parse_four_part_colon_format() {
        let input = "gate.testnet.org:8080:agent007:sample;pass;99";
        let cfg = Socks5Config::parse(input).unwrap();
        assert_eq!(cfg.server, "gate.testnet.org");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.username.as_deref(), Some("agent007"));
        assert_eq!(cfg.password.as_deref(), Some("sample;pass;99"));
    }

    #[test]
    fn test_parse_no_auth() {
        let input = "198.51.100.10:1080";
        let cfg = Socks5Config::parse(input).unwrap();
        assert_eq!(cfg.server, "198.51.100.10");
        assert_eq!(cfg.port, 1080);
        assert!(cfg.username.is_none());
        assert!(cfg.password.is_none());
        assert_eq!(cfg.redacted_string(), "socks5://198.51.100.10:1080");
    }

    #[test]
    fn test_parse_ipv6_literal() {
        let input = "socks5://admin:token@[2001:db8::2]:9999";
        let cfg = Socks5Config::parse(input).unwrap();
        assert_eq!(cfg.server, "2001:db8::2");
        assert_eq!(cfg.port, 9999);
        assert_eq!(cfg.username.as_deref(), Some("admin"));
        assert_eq!(cfg.password.as_deref(), Some("token"));
    }
}
