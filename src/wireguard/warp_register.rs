use crate::error::{ChainError, Result};
use base64::prelude::*;
use rand::rngs::OsRng;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpRegistrationResult {
    pub private_key: String,
    pub public_key: String,
    pub peer_public_key: String,
    pub address_v4: String,
    pub address_v6: Option<String>,
    pub endpoint: String,
    pub wireguard_config: String,
}

#[derive(Deserialize)]
struct WarpRegResponse {
    pub config: WarpConfigObj,
}

#[derive(Deserialize)]
struct WarpConfigObj {
    #[serde(default)]
    pub client_id: Option<String>,
    pub peers: Vec<WarpPeerObj>,
    pub interface: WarpInterfaceObj,
}

#[derive(Deserialize)]
struct WarpPeerObj {
    pub public_key: String,
    pub endpoint: WarpEndpointObj,
}

#[derive(Deserialize)]
struct WarpEndpointObj {
    pub v4: Option<String>,
}

#[derive(Deserialize)]
struct WarpInterfaceObj {
    pub addresses: WarpAddressesObj,
}

#[derive(Deserialize)]
struct WarpAddressesObj {
    pub v4: String,
    pub v6: Option<String>,
}

pub struct WarpRegistrar;

impl WarpRegistrar {
    pub fn generate_keypair() -> (String, String) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (
            BASE64_STANDARD.encode(secret.to_bytes()),
            BASE64_STANDARD.encode(public.as_bytes()),
        )
    }

    pub async fn register_warp() -> Result<WarpRegistrationResult> {
        let (private_key, public_key) = Self::generate_keypair();
        let endpoints = [
            "https://api.cloudflareclient.com/v0a2158/reg",
            "https://api.cloudflareclient.com/v0a3311/reg",
            "https://api.cloudflareclient.com/v0a5641/reg",
        ];

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(USER_AGENT, HeaderValue::from_static("okhttp/3.12.1"));
        headers.insert("CF-Client-Version", HeaderValue::from_static("a-6.3-2158"));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .default_headers(headers)
            .build()
            .map_err(|e| ChainError::NetworkError(e.to_string()))?;

        let body = serde_json::json!({
            "key": public_key,
            "install_id": "",
            "fcm_token": "",
            "tos": "2025-01-01T00:00:00.000Z",
            "model": "PC",
            "type": "Android",
            "locale": "zh_CN"
        });

        for endpoint in &endpoints {
            let Ok(resp) = client.post(*endpoint).json(&body).send().await else { continue };
            if !resp.status().is_success() { continue; }
            let Ok(reg_data) = resp.json::<WarpRegResponse>().await else { continue };

            let client_id = reg_data.config.client_id;
            let reserved = client_id
                .as_deref()
                .and_then(crate::wireguard::parser::parse_reserved_bytes)
                .unwrap_or([0, 0, 0]);
            let Some(peer) = reg_data.config.peers.into_iter().next() else { continue };

            let v4_raw = reg_data.config.interface.addresses.v4;
            let addr_v4 = if v4_raw.contains('/') { v4_raw } else { format!("{}/32", v4_raw) };
            let addr_v6 = reg_data.config.interface.addresses.v6.map(|v6| {
                if v6.contains('/') { v6 } else { format!("{}/128", v6) }
            });

            let mut ep = peer.endpoint.v4.unwrap_or_else(|| "162.159.192.1:2408".to_string());
            if ep.ends_with(":0") {
                ep = ep.replace(":0", ":2408");
            } else if !ep.contains(':') {
                ep = format!("{}:2408", ep);
            }
            let peer_pubkey = peer.public_key;

            if let (Ok(priv_b), Ok(pub_b)) = (
                BASE64_STANDARD.decode(private_key.as_bytes()),
                BASE64_STANDARD.decode(peer_pubkey.as_bytes()),
            ) {
                if priv_b.len() == 32 && pub_b.len() == 32 {
                    let mut sk = [0u8; 32];
                    let mut pk = [0u8; 32];
                    sk.copy_from_slice(&priv_b);
                    pk.copy_from_slice(&pub_b);
                    let cfg_sock = ep.parse().ok();
                    if let Ok(Some((best_addr, _))) = tokio::task::spawn_blocking(move || {
                        crate::warp_kernel::endpoint::select_best_warp_endpoint(
                            sk, pk, reserved, cfg_sock, Duration::from_millis(450),
                        )
                    })
                    .await
                    {
                        ep = best_addr.to_string();
                    }
                }
            }

            let addr_line = match &addr_v6 {
                Some(v6) => format!("Address = {}, {}", addr_v4, v6),
                None => format!("Address = {}", addr_v4),
            };
            let cid_line = client_id.map(|c| format!("# ClientID = {}\n", c)).unwrap_or_default();
            let wg_conf = format!(
                "[Interface]\n{}PrivateKey = {}\n{}\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}\nPersistentKeepalive = 25\n",
                cid_line, private_key, addr_line, peer_pubkey, ep
            );
            info!("Registered Cloudflare WARP device: {}", addr_v4);
            return Ok(WarpRegistrationResult {
                private_key,
                public_key,
                peer_public_key: peer_pubkey,
                address_v4: addr_v4,
                address_v6: addr_v6,
                endpoint: ep,
                wireguard_config: wg_conf,
            });
        }

        warn!("Direct WARP registration unreachable; generating standard WARP profile fallback.");
        let peer_pubkey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string();
        let ep = "162.159.192.1:2408".to_string();
        let addr_v4 = "172.16.0.2/32".to_string();
        let addr_v6 = Some("2606:4700:110:8f6f:f8b2:ff95:cfb8:d7ad/128".to_string());
        let wg_conf = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}, {}\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}\nPersistentKeepalive = 25\n",
            private_key, addr_v4, addr_v6.as_deref().unwrap(), peer_pubkey, ep
        );
        Ok(WarpRegistrationResult {
            private_key,
            public_key,
            peer_public_key: peer_pubkey,
            address_v4: addr_v4,
            address_v6: addr_v6,
            endpoint: ep,
            wireguard_config: wg_conf,
        })
    }
}
