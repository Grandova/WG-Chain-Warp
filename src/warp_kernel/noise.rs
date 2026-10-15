use crate::error::{ChainError, Result};
use crate::warp_kernel::crypto::{
    aead_decrypt, aead_encrypt, blake2s_hash, blake2s_hash2, blake2s_mac, kdf1, kdf2, kdf3,
    tai64n_now,
};
use base64::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

pub const HANDSHAKE_INIT_LEN: usize = 148;
pub const HANDSHAKE_RESP_LEN: usize = 92;
pub const TRANSPORT_HEADER_LEN: usize = 16;
pub const TRANSPORT_OVERHEAD: usize = 32; // 16-byte header + 16-byte Poly1305 tag

struct PendingHandshake {
    local_index: u32,
    ephemeral_private: StaticSecret,
    chaining_key: [u8; 32],
    hash: [u8; 32],
    started_at: Instant,
}

pub struct WgSession {
    pub local_index: u32,
    pub peer_index: u32,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_nonce: u64,
    pub established_at: Instant,
    pub last_received: Instant,
    pub last_sent: Instant,
}

pub enum DecapOutcome<'a> {
    None,
    HandshakeCompleted { rtt_ms: u64 },
    Keepalive,
    IpPacket(&'a [u8]),
}

/// Lightweight, zero-netstack WireGuard & Cloudflare WARP Noise_IKpsk2 tunnel
pub struct WgTunnel {
    static_private: StaticSecret,
    static_public: [u8; 32],
    peer_static_public: PublicKey,
    peer_static_bytes: [u8; 32],
    preshared_key: [u8; 32],
    mac1_key: [u8; 32],
    pub reserved: [u8; 3],
    pending: Option<PendingHandshake>,
    current: Option<WgSession>,
    previous: Option<WgSession>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_rtt_ms: Option<u64>,
}

impl WgTunnel {
    pub fn from_base64_keys(
        private_key_b64: &str,
        peer_public_key_b64: &str,
        preshared_key_b64: Option<&str>,
        reserved: [u8; 3],
    ) -> Result<Self> {
        let priv_vec = BASE64_STANDARD
            .decode(private_key_b64.trim())
            .map_err(|e| ChainError::ValidationError(format!("Invalid private key base64: {}", e)))?;
        let peer_vec = BASE64_STANDARD
            .decode(peer_public_key_b64.trim())
            .map_err(|e| ChainError::ValidationError(format!("Invalid peer public key base64: {}", e)))?;

        if priv_vec.len() != 32 || peer_vec.len() != 32 {
            return Err(ChainError::ValidationError(
                "WireGuard keys must be 32 bytes".to_string(),
            ));
        }

        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(&priv_vec);
        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(&peer_vec);

        let mut psk_bytes = [0u8; 32];
        if let Some(psk_str) = preshared_key_b64 {
            if !psk_str.trim().is_empty() {
                let decoded = BASE64_STANDARD
                    .decode(psk_str.trim())
                    .map_err(|e| ChainError::ValidationError(format!("Invalid PSK base64: {}", e)))?;
                if decoded.len() == 32 {
                    psk_bytes.copy_from_slice(&decoded);
                }
            }
        }

        Ok(Self::new(priv_bytes, peer_bytes, psk_bytes, reserved))
    }

    pub fn new(
        static_private_bytes: [u8; 32],
        peer_static_bytes: [u8; 32],
        preshared_key: [u8; 32],
        reserved: [u8; 3],
    ) -> Self {
        let static_private = StaticSecret::from(static_private_bytes);
        let static_public = *PublicKey::from(&static_private).as_bytes();
        let peer_static_public = PublicKey::from(peer_static_bytes);
        let mac1_key = blake2s_hash2(LABEL_MAC1, &peer_static_bytes);

        Self {
            static_private,
            static_public,
            peer_static_public,
            peer_static_bytes,
            preshared_key,
            mac1_key,
            reserved,
            pending: None,
            current: None,
            previous: None,
            bytes_sent: 0,
            bytes_received: 0,
            last_rtt_ms: None,
        }
    }

    pub fn has_session(&self) -> bool {
        self.current.is_some()
    }

    pub fn needs_handshake(&self) -> bool {
        match &self.current {
            None => self
                .pending
                .as_ref()
                .map(|p| p.started_at.elapsed() >= Duration::from_millis(800))
                .unwrap_or(true),
            Some(sess) => {
                // Rekey if session is older than 120s or no packet received for 45s
                sess.established_at.elapsed() >= Duration::from_secs(120)
                    || (sess.last_received.elapsed() >= Duration::from_secs(45)
                        && self
                            .pending
                            .as_ref()
                            .map(|p| p.started_at.elapsed() >= Duration::from_secs(3))
                            .unwrap_or(true))
            }
        }
    }

    pub fn needs_keepalive(&self) -> bool {
        if let Some(ref sess) = self.current {
            sess.last_sent.elapsed() >= Duration::from_secs(20)
        } else {
            false
        }
    }

    /// Generate a 148-byte WireGuard Type 1 Handshake Initiation packet
    pub fn format_handshake_initiation(&mut self) -> [u8; HANDSHAKE_INIT_LEN] {
        let mut c = blake2s_hash(CONSTRUCTION);
        let mut h = blake2s_hash2(&c, IDENTIFIER);
        h = blake2s_hash2(&h, &self.peer_static_bytes);

        let ephemeral_private = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = *PublicKey::from(&ephemeral_private).as_bytes();

        c = kdf1(&c, &ephemeral_public);
        h = blake2s_hash2(&h, &ephemeral_public);

        let dh_es = ephemeral_private.diffie_hellman(&self.peer_static_public);
        let (c_next, k1) = kdf2(&c, dh_es.as_bytes());
        c = c_next;

        let mut encrypted_static = [0u8; 48];
        aead_encrypt(&k1, 0, &self.static_public, &h, &mut encrypted_static);
        h = blake2s_hash2(&h, &encrypted_static);

        let dh_ss = self.static_private.diffie_hellman(&self.peer_static_public);
        let (c_next2, k2) = kdf2(&c, dh_ss.as_bytes());
        c = c_next2;

        let ts = tai64n_now();
        let mut encrypted_ts = [0u8; 28];
        aead_encrypt(&k2, 0, &ts, &h, &mut encrypted_ts);
        h = blake2s_hash2(&h, &encrypted_ts);

        let local_index = (OsRng.next_u32() & 0x7fff_ffff).max(1);
        let mut msg = [0u8; HANDSHAKE_INIT_LEN];
        msg[0] = 1;
        msg[4..8].copy_from_slice(&local_index.to_le_bytes());
        msg[8..40].copy_from_slice(&ephemeral_public);
        msg[40..88].copy_from_slice(&encrypted_static);
        msg[88..116].copy_from_slice(&encrypted_ts);

        // WireGuard mac1 is always computed with bytes 1..4 zeroed; Cloudflare WARP stamps reserved bytes after mac1
        let mac1 = blake2s_mac(&self.mac1_key, &msg[0..116]);
        msg[1..4].copy_from_slice(&self.reserved);
        msg[116..132].copy_from_slice(&mac1);
        // msg[132..148] is mac2 (zeros when no cookie challenge)

        self.pending = Some(PendingHandshake {
            local_index,
            ephemeral_private,
            chaining_key: c,
            hash: h,
            started_at: Instant::now(),
        });

        self.bytes_sent += HANDSHAKE_INIT_LEN as u64;
        msg
    }

    /// Process a 92-byte WireGuard Type 2 Handshake Response packet
    pub fn consume_handshake_response(&mut self, msg: &[u8]) -> Option<u64> {
        if msg.len() < HANDSHAKE_RESP_LEN || msg[0] != 2 {
            return None;
        }

        let pending = self.pending.as_ref()?;
        let peer_index = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
        let receiver_index = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        if receiver_index != pending.local_index {
            return None;
        }

        let mut peer_ephemeral_bytes = [0u8; 32];
        peer_ephemeral_bytes.copy_from_slice(&msg[12..44]);
        let peer_ephemeral_pub = PublicKey::from(peer_ephemeral_bytes);
        let encrypted_nothing = &msg[44..60];

        let mut c = kdf1(&pending.chaining_key, &peer_ephemeral_bytes);
        let mut h = blake2s_hash2(&pending.hash, &peer_ephemeral_bytes);

        let dh_ee = pending
            .ephemeral_private
            .diffie_hellman(&peer_ephemeral_pub);
        c = kdf1(&c, dh_ee.as_bytes());

        let dh_se = self.static_private.diffie_hellman(&peer_ephemeral_pub);
        c = kdf1(&c, dh_se.as_bytes());

        let (c_next, tau, k) = kdf3(&c, &self.preshared_key);
        c = c_next;
        h = blake2s_hash2(&h, &tau);

        let mut empty_out = [0u8; 0];
        if aead_decrypt(&k, 0, encrypted_nothing, &h, &mut empty_out) != Some(0) {
            return None;
        }

        let (send_key, recv_key) = kdf2(&c, &[]);
        let rtt_ms = pending.started_at.elapsed().as_millis() as u64;
        let local_index = pending.local_index;
        self.pending = None;

        if let Some(prev) = self.current.take() {
            self.previous = Some(prev);
        }

        let now = Instant::now();
        self.current = Some(WgSession {
            local_index,
            peer_index,
            send_key,
            recv_key,
            send_nonce: 0,
            established_at: now,
            last_received: now,
            last_sent: now,
        });
        self.last_rtt_ms = Some(rtt_ms);
        self.bytes_received += msg.len() as u64;

        Some(rtt_ms)
    }

    /// Encapsulate an IPv4/IPv6 packet into a WireGuard Type 4 Transport Data packet
    pub fn encapsulate(&mut self, ip_packet: &[u8], out_buf: &mut [u8]) -> Option<usize> {
        let sess = self.current.as_mut()?;
        let padded_len = if ip_packet.is_empty() {
            0
        } else {
            (ip_packet.len() + 15) & !15
        };

        if out_buf.len() < TRANSPORT_HEADER_LEN + padded_len + 16 {
            return None;
        }

        let nonce = sess.send_nonce;
        sess.send_nonce = sess.send_nonce.wrapping_add(1);
        sess.last_sent = Instant::now();

        out_buf[0] = 4;
        out_buf[1..4].copy_from_slice(&self.reserved);
        out_buf[4..8].copy_from_slice(&sess.peer_index.to_le_bytes());
        out_buf[8..16].copy_from_slice(&nonce.to_le_bytes());

        let mut padded = [0u8; 2048];
        if padded_len > padded.len() {
            let mut vec_pad = vec![0u8; padded_len];
            vec_pad[..ip_packet.len()].copy_from_slice(ip_packet);
            let enc_len = aead_encrypt(
                &sess.send_key,
                nonce,
                &vec_pad,
                &[],
                &mut out_buf[TRANSPORT_HEADER_LEN..],
            );
            let total = TRANSPORT_HEADER_LEN + enc_len;
            self.bytes_sent += total as u64;
            return Some(total);
        }

        padded[..ip_packet.len()].copy_from_slice(ip_packet);
        let enc_len = aead_encrypt(
            &sess.send_key,
            nonce,
            &padded[..padded_len],
            &[],
            &mut out_buf[TRANSPORT_HEADER_LEN..],
        );
        let total = TRANSPORT_HEADER_LEN + enc_len;
        self.bytes_sent += total as u64;
        Some(total)
    }

    /// Generate a 32-byte WireGuard Type 4 Keepalive packet
    pub fn encapsulate_keepalive(&mut self, out_buf: &mut [u8]) -> Option<usize> {
        self.encapsulate(&[], out_buf)
    }

    /// Decapsulate an incoming WireGuard packet (Type 2 HandshakeResponse or Type 4 TransportData)
    pub fn decapsulate<'a>(&mut self, packet: &[u8], out_buf: &'a mut [u8]) -> DecapOutcome<'a> {
        if packet.len() < 4 {
            return DecapOutcome::None;
        }

        match packet[0] {
            2 => {
                if let Some(rtt_ms) = self.consume_handshake_response(packet) {
                    DecapOutcome::HandshakeCompleted { rtt_ms }
                } else {
                    DecapOutcome::None
                }
            }
            4 => {
                if packet.len() < TRANSPORT_OVERHEAD {
                    return DecapOutcome::None;
                }
                let receiver_index =
                    u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
                let counter = u64::from_le_bytes([
                    packet[8], packet[9], packet[10], packet[11], packet[12], packet[13],
                    packet[14], packet[15],
                ]);

                let plain_len = if let Some(ref mut sess) = self.current {
                    if sess.local_index == receiver_index {
                        if let Some(len) = aead_decrypt(
                            &sess.recv_key,
                            counter,
                            &packet[TRANSPORT_HEADER_LEN..],
                            &[],
                            out_buf,
                        ) {
                            sess.last_received = Instant::now();
                            Some(len)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
                .or_else(|| {
                    let prev = self.previous.as_mut()?;
                    if prev.local_index == receiver_index {
                        let len = aead_decrypt(
                            &prev.recv_key,
                            counter,
                            &packet[TRANSPORT_HEADER_LEN..],
                            &[],
                            out_buf,
                        )?;
                        prev.last_received = Instant::now();
                        Some(len)
                    } else {
                        None
                    }
                });

                let Some(dec_len) = plain_len else {
                    return DecapOutcome::None;
                };
                self.bytes_received += packet.len() as u64;

                if dec_len == 0 {
                    return DecapOutcome::Keepalive;
                }

                // Strip WireGuard 16-byte block padding using IPv4/IPv6 header length field
                let version = out_buf[0] >> 4;
                if version == 4 && dec_len >= 20 {
                    let ip_len = u16::from_be_bytes([out_buf[2], out_buf[3]]) as usize;
                    if ip_len >= 20 && ip_len <= dec_len {
                        return DecapOutcome::IpPacket(&out_buf[..ip_len]);
                    }
                } else if version == 6 && dec_len >= 40 {
                    let payload_len = u16::from_be_bytes([out_buf[4], out_buf[5]]) as usize;
                    let ip_len = 40 + payload_len;
                    if ip_len <= dec_len {
                        return DecapOutcome::IpPacket(&out_buf[..ip_len]);
                    }
                }

                DecapOutcome::None
            }
            _ => DecapOutcome::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_noise_ikpsk2_handshake_and_transport() {
        let init_priv_bytes = [0x11u8; 32];
        let resp_priv_bytes = [0x22u8; 32];
        let psk = [0x33u8; 32];

        let init_priv = StaticSecret::from(init_priv_bytes);
        let init_pub = *PublicKey::from(&init_priv).as_bytes();
        let resp_priv = StaticSecret::from(resp_priv_bytes);
        let resp_pub = *PublicKey::from(&resp_priv).as_bytes();

        let mut initiator = WgTunnel::new(init_priv_bytes, resp_pub, psk, [12, 34, 56]);
        let msg1 = initiator.format_handshake_initiation();
        assert_eq!(msg1[0], 1);
        assert_eq!(&msg1[1..4], &[12, 34, 56]);

        // Simulate Responder verifying msg1 and generating msg2 (HandshakeResponse)
        let init_idx = u32::from_le_bytes([msg1[4], msg1[5], msg1[6], msg1[7]]);
        let mut e_i_bytes = [0u8; 32];
        e_i_bytes.copy_from_slice(&msg1[8..40]);
        let e_i_pub = PublicKey::from(e_i_bytes);

        let mut c = blake2s_hash(CONSTRUCTION);
        let mut h = blake2s_hash2(&c, IDENTIFIER);
        h = blake2s_hash2(&h, &resp_pub);
        c = kdf1(&c, &e_i_bytes);
        h = blake2s_hash2(&h, &e_i_bytes);

        let dh_es = resp_priv.diffie_hellman(&e_i_pub);
        let (c_next, k1) = kdf2(&c, dh_es.as_bytes());
        c = c_next;

        let mut dec_static = [0u8; 32];
        assert_eq!(
            aead_decrypt(&k1, 0, &msg1[40..88], &h, &mut dec_static),
            Some(32)
        );
        assert_eq!(dec_static, init_pub);
        h = blake2s_hash2(&h, &msg1[40..88]);

        let init_pub_key = PublicKey::from(init_pub);
        let dh_ss = resp_priv.diffie_hellman(&init_pub_key);
        let (c_next2, k2) = kdf2(&c, dh_ss.as_bytes());
        c = c_next2;

        let mut dec_ts = [0u8; 12];
        assert_eq!(
            aead_decrypt(&k2, 0, &msg1[88..116], &h, &mut dec_ts),
            Some(12)
        );
        h = blake2s_hash2(&h, &msg1[88..116]);

        // Responder builds Type 2 HandshakeResponse
        let e_r_priv = StaticSecret::from([0x44u8; 32]);
        let e_r_pub = *PublicKey::from(&e_r_priv).as_bytes();
        c = kdf1(&c, &e_r_pub);
        h = blake2s_hash2(&h, &e_r_pub);
        c = kdf1(&c, e_r_priv.diffie_hellman(&e_i_pub).as_bytes());
        c = kdf1(&c, e_r_priv.diffie_hellman(&init_pub_key).as_bytes());
        let (c_next3, tau, k3) = kdf3(&c, &psk);
        c = c_next3;
        h = blake2s_hash2(&h, &tau);

        let mut enc_nothing = [0u8; 16];
        aead_encrypt(&k3, 0, &[], &h, &mut enc_nothing);
        let (resp_recv_key, resp_send_key) = kdf2(&c, &[]);

        let resp_idx = 99u32;
        let mut msg2 = [0u8; HANDSHAKE_RESP_LEN];
        msg2[0] = 2;
        msg2[4..8].copy_from_slice(&resp_idx.to_le_bytes());
        msg2[8..12].copy_from_slice(&init_idx.to_le_bytes());
        msg2[12..44].copy_from_slice(&e_r_pub);
        msg2[44..60].copy_from_slice(&enc_nothing);

        let mut decap_buf = [0u8; 2048];
        match initiator.decapsulate(&msg2, &mut decap_buf) {
            DecapOutcome::HandshakeCompleted { .. } => {}
            _ => panic!("Expected HandshakeCompleted"),
        }
        assert!(initiator.has_session());

        // Test Initiator -> Responder Transport Data (IPv4 packet of 28 bytes)
        let mut sample_ipv4 = [0u8; 28];
        sample_ipv4[0] = 0x45;
        sample_ipv4[2..4].copy_from_slice(&28u16.to_be_bytes());
        sample_ipv4[12..16].copy_from_slice(&[172, 16, 0, 2]);
        sample_ipv4[16..20].copy_from_slice(&[1, 1, 1, 1]);

        let mut wg_pkt = [0u8; 256];
        let wg_len = initiator.encapsulate(&sample_ipv4, &mut wg_pkt).unwrap();
        assert_eq!(wg_pkt[0], 4);
        assert_eq!(&wg_pkt[1..4], &[12, 34, 56]); // Cloudflare WARP reserved bytes preserved

        // Responder decrypts Transport Data
        let mut resp_plain = [0u8; 128];
        let dec_len = aead_decrypt(&resp_recv_key, 0, &wg_pkt[16..wg_len], &[], &mut resp_plain).unwrap();
        assert_eq!(dec_len, 32); // padded to 16-byte multiple
        assert_eq!(&resp_plain[..28], &sample_ipv4[..]);

        // Responder -> Initiator Transport Data
        let mut reply_wg = [0u8; 128];
        reply_wg[0] = 4;
        reply_wg[4..8].copy_from_slice(&init_idx.to_le_bytes());
        reply_wg[8..16].copy_from_slice(&0u64.to_le_bytes());
        let enc_len = aead_encrypt(&resp_send_key, 0, &resp_plain[..32], &[], &mut reply_wg[16..]);
        match initiator.decapsulate(&reply_wg[..16 + enc_len], &mut decap_buf) {
            DecapOutcome::IpPacket(pkt) => {
                assert_eq!(pkt, &sample_ipv4[..]);
            }
            _ => panic!("Expected IpPacket"),
        }
    }
}
