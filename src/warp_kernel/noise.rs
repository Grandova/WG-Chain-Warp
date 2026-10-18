use crate::warp_kernel::crypto::{
    aead_decrypt, aead_encrypt, aead_encrypt_in_place, blake2s_hash, blake2s_hash2, blake2s_mac,
    kdf1, kdf2, kdf3, tai64n_now,
};
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
pub const TRANSPORT_OVERHEAD: usize = 32;
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

struct PendingHandshake {
    local_index: u32,
    ephemeral_private: StaticSecret,
    chaining_key: [u8; 32],
    hash: [u8; 32],
    started_at: Instant,
    retry_after: Duration,
}

pub struct WgSession {
    pub local_index: u32,
    pub peer_index: u32,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_nonce: u64,
    recv_nonce: u64,
    recv_window: [u64; 128],
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

pub struct WgTunnel {
    static_private: StaticSecret,
    static_public: [u8; 32],
    peer_static_public: PublicKey,
    peer_static_bytes: [u8; 32],
    preshared_key: [u8; 32],
    mac1_key: [u8; 32],
    pub reserved: [u8; 3],
    pending: Option<PendingHandshake>,
    prev_pending: Option<PendingHandshake>,
    current: Option<WgSession>,
    previous: Option<WgSession>,
}

impl WgTunnel {
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
            prev_pending: None,
            current: None,
            previous: None,
        }
    }

    pub fn has_session(&self) -> bool {
        self.current
            .as_ref()
            .map(|s| {
                s.established_at.elapsed() < REJECT_AFTER_TIME
                    && s.send_nonce < REJECT_AFTER_MESSAGES
            })
            .unwrap_or(false)
    }

    pub fn expire_if_dead(&mut self) -> bool {
        if self
            .previous
            .as_ref()
            .is_some_and(|s| s.established_at.elapsed() >= REJECT_AFTER_TIME)
        {
            self.previous = None;
        }
        if let Some(ref sess) = self.current {
            if sess.established_at.elapsed() >= REJECT_AFTER_TIME {
                self.current = None;
                return true;
            }
        }
        false
    }

    pub fn needs_handshake(&self) -> bool {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.started_at.elapsed() < p.retry_after)
        {
            return false;
        }
        match &self.current {
            None => true,
            Some(sess) => {
                sess.established_at.elapsed() >= Duration::from_secs(120)
                    || sess.send_nonce >= (1 << 60)
                    || sess.last_received.elapsed() >= Duration::from_secs(25)
            }
        }
    }

    pub fn needs_keepalive(&self) -> bool {
        self.current
            .as_ref()
            .map(|s| {
                s.last_sent.elapsed() >= Duration::from_secs(15)
                    || (s.last_received.elapsed() >= Duration::from_secs(15)
                        && s.last_sent.elapsed() >= Duration::from_secs(5))
            })
            .unwrap_or(false)
    }

    pub fn format_handshake_initiation(&mut self) -> [u8; HANDSHAKE_INIT_LEN] {
        let mut c = blake2s_hash(CONSTRUCTION);
        let mut h = blake2s_hash2(&c, IDENTIFIER);
        h = blake2s_hash2(&h, &self.peer_static_bytes);

        let ephemeral_private = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = *PublicKey::from(&ephemeral_private).as_bytes();
        c = kdf1(&c, &ephemeral_public);
        h = blake2s_hash2(&h, &ephemeral_public);

        let (c_next, k1) = kdf2(&c, ephemeral_private.diffie_hellman(&self.peer_static_public).as_bytes());
        c = c_next;

        let mut enc_static = [0u8; 48];
        aead_encrypt(&k1, 0, &self.static_public, &h, &mut enc_static);
        h = blake2s_hash2(&h, &enc_static);

        let (c_next2, k2) = kdf2(&c, self.static_private.diffie_hellman(&self.peer_static_public).as_bytes());
        c = c_next2;

        let mut enc_ts = [0u8; 28];
        aead_encrypt(&k2, 0, &tai64n_now(), &h, &mut enc_ts);
        h = blake2s_hash2(&h, &enc_ts);

        let local_index = (OsRng.next_u32() & 0x7fff_ffff).max(1);
        let mut msg = [0u8; HANDSHAKE_INIT_LEN];
        msg[0] = 1;
        msg[4..8].copy_from_slice(&local_index.to_le_bytes());
        msg[8..40].copy_from_slice(&ephemeral_public);
        msg[40..88].copy_from_slice(&enc_static);
        msg[88..116].copy_from_slice(&enc_ts);

        let mac1 = blake2s_mac(&self.mac1_key, &msg[0..116]);
        msg[1..4].copy_from_slice(&self.reserved);
        msg[116..132].copy_from_slice(&mac1);

        if let Some(old) = self.pending.take() {
            self.prev_pending = Some(old);
        }
        self.pending = Some(PendingHandshake {
            local_index,
            ephemeral_private,
            chaining_key: c,
            hash: h,
            started_at: Instant::now(),
            retry_after: Duration::from_millis(5000 + u64::from(OsRng.next_u32() % 334)),
        });
        msg
    }

    pub fn consume_handshake_response(&mut self, msg: &[u8]) -> Option<u64> {
        if msg.len() != HANDSHAKE_RESP_LEN || msg[0] != 2 {
            return None;
        }
        let peer_index = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
        let rx_local = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        let pending = if self.pending.as_ref().map(|p| p.local_index) == Some(rx_local) {
            self.pending.as_ref()?
        } else if self.prev_pending.as_ref().map(|p| p.local_index) == Some(rx_local) {
            self.prev_pending.as_ref()?
        } else {
            return None;
        };

        let mut peer_eph = [0u8; 32];
        peer_eph.copy_from_slice(&msg[12..44]);
        let peer_eph_pub = PublicKey::from(peer_eph);

        let mut c = kdf1(&pending.chaining_key, &peer_eph);
        let mut h = blake2s_hash2(&pending.hash, &peer_eph);
        c = kdf1(&c, pending.ephemeral_private.diffie_hellman(&peer_eph_pub).as_bytes());
        c = kdf1(&c, self.static_private.diffie_hellman(&peer_eph_pub).as_bytes());
        let (c_next, tau, k) = kdf3(&c, &self.preshared_key);
        c = c_next;
        h = blake2s_hash2(&h, &tau);

        let mut empty = [0u8; 0];
        if aead_decrypt(&k, 0, &msg[44..60], &h, &mut empty) != Some(0) {
            return None;
        }

        let (send_key, recv_key) = kdf2(&c, &[]);
        let rtt_ms = pending.started_at.elapsed().as_millis() as u64;
        let local_index = pending.local_index;
        self.pending = None;
        self.prev_pending = None;
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
            recv_nonce: 0,
            recv_window: [0; 128],
            established_at: now,
            last_received: now,
            last_sent: now,
        });
        Some(rtt_ms)
    }

    pub fn encapsulate(&mut self, ip_packet: &[u8], out_buf: &mut [u8]) -> Option<usize> {
        let sess = self.current.as_mut()?;
        if sess.established_at.elapsed() >= REJECT_AFTER_TIME
            || sess.send_nonce >= REJECT_AFTER_MESSAGES
        {
            return None;
        }
        let pt_len = ip_packet.len();
        let padded_len = if pt_len == 0 { 0 } else { (pt_len + 15) & !15 };
        if out_buf.len() < TRANSPORT_HEADER_LEN + padded_len + 16 {
            return None;
        }
        let nonce = sess.send_nonce;
        sess.send_nonce += 1;
        sess.last_sent = Instant::now();

        out_buf[0] = 4;
        out_buf[1..4].copy_from_slice(&self.reserved);
        out_buf[4..8].copy_from_slice(&sess.peer_index.to_le_bytes());
        out_buf[8..16].copy_from_slice(&nonce.to_le_bytes());

        let payload_buf = &mut out_buf[TRANSPORT_HEADER_LEN..];
        payload_buf[..pt_len].copy_from_slice(ip_packet);
        if padded_len > pt_len {
            payload_buf[pt_len..padded_len].fill(0);
        }
        let enc_len = aead_encrypt_in_place(&sess.send_key, nonce, &[], payload_buf, padded_len);
        Some(TRANSPORT_HEADER_LEN + enc_len)
    }

    pub fn encapsulate_keepalive(&mut self, out_buf: &mut [u8]) -> Option<usize> {
        self.encapsulate(&[], out_buf)
    }

    pub fn decapsulate<'a>(&mut self, packet: &[u8], out_buf: &'a mut [u8]) -> DecapOutcome<'a> {
        if packet.len() < 4 {
            return DecapOutcome::None;
        }
        match packet[0] {
            2 => self
                .consume_handshake_response(packet)
                .map(|rtt_ms| DecapOutcome::HandshakeCompleted { rtt_ms })
                .unwrap_or(DecapOutcome::None),
            4 if packet.len() >= TRANSPORT_OVERHEAD => {
                let rx_idx = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
                let counter = u64::from_le_bytes(packet[8..16].try_into().unwrap());
                let ct = &packet[TRANSPORT_HEADER_LEN..];

                let sess = self
                    .current
                    .as_mut()
                    .filter(|s| s.local_index == rx_idx)
                    .or_else(|| self.previous.as_mut().filter(|s| s.local_index == rx_idx));
                let Some(sess) = sess else {
                    return DecapOutcome::None;
                };
                if sess.established_at.elapsed() >= REJECT_AFTER_TIME
                    || counter >= REJECT_AFTER_MESSAGES
                {
                    return DecapOutcome::None;
                }
                let Some(dec_len) = aead_decrypt(&sess.recv_key, counter, ct, &[], out_buf) else {
                    return DecapOutcome::None;
                };
                // Advance the replay window only after authenticating the counter and payload.
                let block = counter / 64;
                if counter > sess.recv_nonce {
                    let old_block = sess.recv_nonce / 64;
                    for i in 1..=(block - old_block).min(128) {
                        sess.recv_window[((old_block + i) % 128) as usize] = 0;
                    }
                    sess.recv_nonce = counter;
                } else if sess.recv_nonce - counter > 127 * 64 {
                    return DecapOutcome::None;
                }
                let slot = &mut sess.recv_window[(block % 128) as usize];
                let bit = 1u64 << (counter % 64);
                if *slot & bit != 0 {
                    return DecapOutcome::None;
                }
                *slot |= bit;
                sess.last_received = Instant::now();
                if dec_len == 0 {
                    return DecapOutcome::Keepalive;
                }
                let ver = out_buf[0] >> 4;
                if ver == 4 && dec_len >= 20 {
                    let ip_len = u16::from_be_bytes([out_buf[2], out_buf[3]]) as usize;
                    let ihl = usize::from(out_buf[0] & 0x0f) * 4;
                    if ihl >= 20 && (ihl..=dec_len).contains(&ip_len) {
                        return DecapOutcome::IpPacket(&out_buf[..ip_len]);
                    }
                } else if ver == 6 && dec_len >= 40 {
                    let ip_len = 40 + u16::from_be_bytes([out_buf[4], out_buf[5]]) as usize;
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
    use boringtun::noise::{Tunn, TunnResult};

    fn peer_pair() -> (WgTunnel, Tunn) {
        let local_key = StaticSecret::from([7; 32]);
        let peer_key = StaticSecret::from([9; 32]);
        let local = WgTunnel::new(
            local_key.to_bytes(),
            PublicKey::from(&peer_key).to_bytes(),
            [3; 32],
            [0; 3],
        );
        let peer = Tunn::new(
            peer_key,
            PublicKey::from(&local_key),
            Some([3; 32]),
            None,
            123,
            None,
        );
        (local, peer)
    }

    fn handshake(local: &mut WgTunnel, peer: &mut Tunn) {
        let init = local.format_handshake_initiation();
        let mut buf = [0u8; 2048];
        let TunnResult::WriteToNetwork(response) = peer.decapsulate(None, &init, &mut buf) else {
            panic!("BoringTun rejected the initiation");
        };
        assert!(local.consume_handshake_response(response).is_some());
        let mut confirm = [0u8; 64];
        let n = local.encapsulate_keepalive(&mut confirm).unwrap();
        assert!(matches!(
            peer.decapsulate(None, &confirm[..n], &mut buf),
            TunnResult::Done
        ));
    }

    fn packet() -> Vec<u8> {
        let mut buf = [0u8; 64];
        let n = crate::warp_kernel::pkt::wrap_ipv4_udp(
            b"round trip",
            "10.0.0.1".parse().unwrap(),
            1234,
            "10.0.0.2".parse().unwrap(),
            4321,
            1,
            &mut buf,
        );
        buf[..n].to_vec()
    }

    #[test]
    fn boringtun_rekey_preserves_traffic_and_delayed_response() {
        let (mut local, mut peer) = peer_pair();
        handshake(&mut local, &mut peer);
        let packet = packet();
        let mut wire = [0u8; 2048];
        let mut plain = [0u8; 2048];
        for _ in 0..3 {
            local.current.as_mut().unwrap().established_at -= Duration::from_secs(121);
            local.current.as_mut().unwrap().last_received -= Duration::from_secs(39);
            assert!(!local.expire_if_dead());
            assert!(local.has_session());
            assert!(local.needs_handshake());
            let init = local.format_handshake_initiation();
            local.pending.as_mut().unwrap().started_at -= Duration::from_secs(4);
            assert!(!local.needs_handshake());
            let n = local.encapsulate(&packet, &mut wire).unwrap();
            let TunnResult::WriteToTunnelV4(data, _) =
                peer.decapsulate(None, &wire[..n], &mut plain)
            else {
                panic!("traffic stopped during rekey");
            };
            assert_eq!(data, packet);
            let response = match peer.decapsulate(None, &init, &mut wire) {
                TunnResult::WriteToNetwork(response) => response,
                result => panic!("rekey failed: {:?}", result),
            };
            assert!(local.consume_handshake_response(response).is_some());
            let n = local.encapsulate_keepalive(&mut wire).unwrap();
            assert!(matches!(
                peer.decapsulate(None, &wire[..n], &mut plain),
                TunnResult::Done
            ));
            let TunnResult::WriteToNetwork(response) = peer.encapsulate(&packet, &mut wire) else {
                panic!("peer has no session");
            };
            let DecapOutcome::IpPacket(data) = local.decapsulate(response, &mut plain) else {
                panic!("return traffic failed after rekey");
            };
            assert_eq!(data, packet);
        }
    }

    #[test]
    fn boringtun_reordered_packets_replay_and_expired_keys() {
        let (mut local, mut peer) = peer_pair();
        handshake(&mut local, &mut peer);
        let mut buf = [0u8; 2048];
        let mut frames = Vec::new();
        for _ in 0..3 {
            let TunnResult::WriteToNetwork(frame) = peer.encapsulate(&packet(), &mut buf) else {
                panic!("peer has no session");
            };
            frames.push(frame.to_vec());
        }
        let mut forged = frames[2].clone();
        forged[8..16].copy_from_slice(&1_000_000u64.to_le_bytes());
        assert!(matches!(
            local.decapsulate(&forged, &mut buf),
            DecapOutcome::None
        ));
        for i in [1, 0] {
            assert!(matches!(
                local.decapsulate(&frames[i], &mut buf),
                DecapOutcome::IpPacket(_)
            ));
            assert!(matches!(
                local.decapsulate(&frames[i], &mut buf),
                DecapOutcome::None
            ));
        }
        handshake(&mut local, &mut peer);
        assert!(matches!(
            local.decapsulate(&frames[2], &mut buf),
            DecapOutcome::IpPacket(_)
        ));
        local.previous.as_mut().unwrap().established_at -= REJECT_AFTER_TIME;
        assert!(matches!(
            local.decapsulate(&frames[2], &mut buf),
            DecapOutcome::None
        ));
        local.current.as_mut().unwrap().send_nonce = REJECT_AFTER_MESSAGES;
        assert!(local.encapsulate_keepalive(&mut buf).is_none());
        assert!(local.needs_handshake());
        local.current.as_mut().unwrap().established_at -= REJECT_AFTER_TIME;
        assert!(local.expire_if_dead());
        assert!(local.previous.is_none());
        assert!(!local.has_session());
    }

    #[test]
    fn handshake_retries_are_rate_limited_and_truncated_packets_rejected() {
        let (mut local, mut peer) = peer_pair();
        assert!(local.needs_handshake());
        let init = local.format_handshake_initiation();
        local.pending.as_mut().unwrap().started_at -= Duration::from_secs(4);
        assert!(!local.needs_handshake());
        local.pending.as_mut().unwrap().started_at -= Duration::from_secs(2);
        assert!(local.needs_handshake());
        let mut buf = [0u8; 2048];
        let TunnResult::WriteToNetwork(response) = peer.decapsulate(None, &init, &mut buf) else {
            panic!("peer rejected initiation");
        };
        for n in 0..response.len() {
            assert!(local.consume_handshake_response(&response[..n]).is_none());
        }
        assert!(local.consume_handshake_response(response).is_some());
        let mut plain = [0u8; 2048];
        for n in 0..32 {
            buf[0] = 4;
            assert!(matches!(
                local.decapsulate(&buf[..n], &mut plain),
                DecapOutcome::None
            ));
        }
    }
}
