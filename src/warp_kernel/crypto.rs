use std::time::{SystemTime, UNIX_EPOCH};

/// RFC 7693 BLAKE2s Initialization Vector
const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// RFC 7693 BLAKE2s Message Word Permutation Schedule
const BLAKE2S_SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[inline(always)]
fn blake2s_g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

fn blake2s_compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool) {
    let mut v = [0u32; 16];
    v[0..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&BLAKE2S_IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] = !v[14];
    }

    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    for s in &BLAKE2S_SIGMA {
        blake2s_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        blake2s_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        blake2s_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        blake2s_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        blake2s_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        blake2s_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        blake2s_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        blake2s_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Core BLAKE2s variable-digest, optional-key implementation (RFC 7693)
fn blake2s_raw(key: &[u8], data: &[u8], out: &mut [u8]) {
    debug_assert!(!out.is_empty() && out.len() <= 32);
    debug_assert!(key.len() <= 32);

    let mut h = BLAKE2S_IV;
    h[0] ^= 0x01010000 ^ ((key.len() as u32) << 8) ^ (out.len() as u32);

    let mut buf = [0u8; 64];
    let mut buflen: usize = 0;
    let mut total: u64 = 0;

    if !key.is_empty() {
        buf[..key.len()].copy_from_slice(key);
        buflen = 64;
    }

    for &byte in data {
        if buflen == 64 {
            total += 64;
            blake2s_compress(&mut h, &buf, total, false);
            buflen = 0;
        }
        buf[buflen] = byte;
        buflen += 1;
    }

    total += buflen as u64;
    for b in &mut buf[buflen..64] {
        *b = 0;
    }
    blake2s_compress(&mut h, &buf, total, true);

    let mut full = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        full[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out.copy_from_slice(&full[..out.len()]);
}

/// WireGuard HASH(input): unkeyed BLAKE2s-256
pub fn blake2s_hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    blake2s_raw(&[], data, &mut out);
    out
}

/// WireGuard HASH(a || b) helper without heap allocation
pub fn blake2s_hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = BLAKE2S_IV;
    h[0] ^= 0x01010020; // outlen = 32, keylen = 0
    let mut buf = [0u8; 64];
    let mut buflen = 0usize;
    let mut total = 0u64;

    for &byte in a.iter().chain(b.iter()) {
        if buflen == 64 {
            total += 64;
            blake2s_compress(&mut h, &buf, total, false);
            buflen = 0;
        }
        buf[buflen] = byte;
        buflen += 1;
    }
    total += buflen as u64;
    buf[buflen..64].fill(0);
    blake2s_compress(&mut h, &buf, total, true);

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// WireGuard MAC(key, input): keyed BLAKE2s-128 (16-byte tag)
pub fn blake2s_mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    blake2s_raw(key, data, &mut out);
    out
}

/// WireGuard HMAC-BLAKE2s-256 (RFC 2104, block size 64, digest size 32)
pub fn hmac_blake2s(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let hashed = blake2s_hash(key);
        k_pad[..32].copy_from_slice(&hashed);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_pad[i];
        opad[i] ^= k_pad[i];
    }

    let inner = blake2s_hash2(&ipad, input);
    blake2s_hash2(&opad, &inner)
}

pub fn kdf1(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let prk = hmac_blake2s(key, input);
    hmac_blake2s(&prk, &[0x01])
}

pub fn kdf2(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&prk, &[0x01]);
    let mut t1_plus = [0u8; 33];
    t1_plus[..32].copy_from_slice(&t1);
    t1_plus[32] = 0x02;
    let t2 = hmac_blake2s(&prk, &t1_plus);
    (t1, t2)
}

pub fn kdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let prk = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&prk, &[0x01]);
    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(&t1);
    buf[32] = 0x02;
    let t2 = hmac_blake2s(&prk, &buf);
    buf[..32].copy_from_slice(&t2);
    buf[32] = 0x03;
    let t3 = hmac_blake2s(&prk, &buf);
    (t1, t2, t3)
}

// ============================================================================
// RFC 8439 ChaCha20-Poly1305 AEAD
// ============================================================================

#[inline(always)]
fn chacha_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;

    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }
    state[12] = counter;
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let initial = state;
    for _ in 0..10 {
        chacha_quarter_round(&mut state, 0, 4, 8, 12);
        chacha_quarter_round(&mut state, 1, 5, 9, 13);
        chacha_quarter_round(&mut state, 2, 6, 10, 14);
        chacha_quarter_round(&mut state, 3, 7, 11, 15);
        chacha_quarter_round(&mut state, 0, 5, 10, 15);
        chacha_quarter_round(&mut state, 1, 6, 11, 12);
        chacha_quarter_round(&mut state, 2, 7, 8, 13);
        chacha_quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = state[i].wrapping_add(initial[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn chacha20_xor(key: &[u8; 32], initial_counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut counter = initial_counter;
    for chunk in data.chunks_mut(64) {
        let block = chacha20_block(key, counter, nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= *k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Poly1305 State using 5x 26-bit limbs (RFC 8439)
struct Poly1305 {
    r: [u64; 5],
    s: [u64; 4],
    h: [u64; 5],
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let r0 = (u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x3fff_ffff) as u64;
        let r1 = (u32::from_le_bytes([key[3], key[4], key[5], key[6]]) >> 2 & 0x3fff_fc03) as u64;
        let r2 = (u32::from_le_bytes([key[6], key[7], key[8], key[9]]) >> 4 & 0x3ffc_0ff0) as u64;
        let r3 = (u32::from_le_bytes([key[9], key[10], key[11], key[12]]) >> 6 & 0x3f03_fc0f) as u64;
        let r4 = (u32::from_le_bytes([key[12], key[13], key[14], key[15]]) >> 8 & 0x000f_fffc) as u64;

        // Clean 26-bit clamped limb extraction from 128-bit clamped r:
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[0..16]);
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;
        let r_u128 = u128::from_le_bytes(r_bytes);
        let _ = (r0, r1, r2, r3, r4);

        let r = [
            (r_u128 & 0x3ff_ffff) as u64,
            ((r_u128 >> 26) & 0x3ff_ffff) as u64,
            ((r_u128 >> 52) & 0x3ff_ffff) as u64,
            ((r_u128 >> 78) & 0x3ff_ffff) as u64,
            ((r_u128 >> 104) & 0x3ff_ffff) as u64,
        ];

        let s = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]) as u64,
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]) as u64,
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]) as u64,
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]) as u64,
        ];

        Self { r, s, h: [0; 5] }
    }

    fn block(&mut self, block: &[u8; 16], hibit: u64) {
        let m = u128::from_le_bytes(*block);
        let mut h0 = self.h[0] + ((m & 0x3ff_ffff) as u64);
        let mut h1 = self.h[1] + (((m >> 26) & 0x3ff_ffff) as u64);
        let mut h2 = self.h[2] + (((m >> 52) & 0x3ff_ffff) as u64);
        let mut h3 = self.h[3] + (((m >> 78) & 0x3ff_ffff) as u64);
        let mut h4 = self.h[4] + (((m >> 104) & 0x3ff_ffff) as u64) + (hibit << 24);

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h0 = d0 & 0x3ff_ffff;
        d1 += c;
        c = d1 >> 26;
        h1 = d1 & 0x3ff_ffff;
        d2 += c;
        c = d2 >> 26;
        h2 = d2 & 0x3ff_ffff;
        d3 += c;
        c = d3 >> 26;
        h3 = d3 & 0x3ff_ffff;
        d4 += c;
        c = d4 >> 26;
        h4 = d4 & 0x3ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        self.h = [h0, h1, h2, h3, h4];
    }

    fn update_padded(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            self.block(&block, 1);
        }
    }

    fn finalize(self) -> [u8; 16] {
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ff_ffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ff_ffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ff_ffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 63).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let inv_mask = !mask;
        h0 = (h0 & inv_mask) | g0;
        h1 = (h1 & inv_mask) | g1;
        h2 = (h2 & inv_mask) | g2;
        h3 = (h3 & inv_mask) | g3;
        h4 = (h4 & inv_mask) | (g4 & mask);

        let w0 = ((h0) | (h1 << 26)) & 0xffff_ffff;
        let w1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
        let w2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
        let w3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

        let mut f = w0 + self.s[0];
        let o0 = f as u32;
        f = w1 + self.s[1] + (f >> 32);
        let o1 = f as u32;
        f = w2 + self.s[2] + (f >> 32);
        let o2 = f as u32;
        f = w3 + self.s[3] + (f >> 32);
        let o3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&o0.to_le_bytes());
        tag[4..8].copy_from_slice(&o1.to_le_bytes());
        tag[8..12].copy_from_slice(&o2.to_le_bytes());
        tag[12..16].copy_from_slice(&o3.to_le_bytes());
        tag
    }
}

fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut poly = Poly1305::new(otk);
    poly.update_padded(aad);
    poly.update_padded(ciphertext);
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.block(&lens, 1);
    poly.finalize()
}

/// WireGuard AEAD_ENCRYPT(key, counter, plaintext, aad) -> writes plaintext.len() + 16 bytes into `out`
pub fn aead_encrypt(
    key: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> usize {
    debug_assert!(out.len() >= plaintext.len() + 16);
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());

    let block0 = chacha20_block(key, 0, &nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[0..32]);

    let ct_len = plaintext.len();
    out[..ct_len].copy_from_slice(plaintext);
    chacha20_xor(key, 1, &nonce, &mut out[..ct_len]);

    let tag = poly1305_aead_tag(&otk, aad, &out[..ct_len]);
    out[ct_len..ct_len + 16].copy_from_slice(&tag);
    ct_len + 16
}

/// WireGuard AEAD_DECRYPT(key, counter, ciphertext_with_tag, aad) -> writes plaintext into `out`
pub fn aead_decrypt(
    key: &[u8; 32],
    counter: u64,
    ciphertext_with_tag: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if ciphertext_with_tag.len() < 16 {
        return None;
    }
    let ct_len = ciphertext_with_tag.len() - 16;
    if out.len() < ct_len {
        return None;
    }

    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());

    let block0 = chacha20_block(key, 0, &nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[0..32]);

    let expected_tag = poly1305_aead_tag(&otk, aad, &ciphertext_with_tag[..ct_len]);
    let provided_tag = &ciphertext_with_tag[ct_len..];

    // Constant-time tag comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected_tag[i] ^ provided_tag[i];
    }
    if diff != 0 {
        return None;
    }

    out[..ct_len].copy_from_slice(&ciphertext_with_tag[..ct_len]);
    chacha20_xor(key, 1, &nonce, &mut out[..ct_len]);
    Some(ct_len)
}

/// TAI64N timestamp (12 bytes) monotonically increasing
pub fn tai64n_now() -> [u8; 12] {
    static LAST_TS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = 0x4000_0000_0000_000au64.wrapping_add(dur.as_secs());
    let nanos = (dur.subsec_nanos() & 0xffff_ff00) as u64;
    let packed = (secs << 20) | (nanos >> 12);
    let prev = LAST_TS.fetch_max(packed, std::sync::atomic::Ordering::SeqCst);
    let final_secs = if packed <= prev {
        secs.wrapping_add(1)
    } else {
        secs
    };
    let mut out = [0u8; 12];
    out[0..8].copy_from_slice(&final_secs.to_be_bytes());
    out[8..12].copy_from_slice(&(nanos as u32).to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc7693_blake2s_vectors() {
        // Empty input BLAKE2s-256 test vector
        let empty_hash = blake2s_hash(b"");
        let expected_empty: [u8; 32] = [
            0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94,
            0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
            0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e,
            0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9,
        ];
        assert_eq!(empty_hash, expected_empty);

        // "abc" BLAKE2s-256 test vector (RFC 7693 Appendix A)
        let abc_hash = blake2s_hash(b"abc");
        let expected_abc: [u8; 32] = [
            0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2,
            0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
            0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29,
            0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82,
        ];
        assert_eq!(abc_hash, expected_abc);
        assert_eq!(blake2s_hash2(b"a", b"bc"), expected_abc);
    }

    #[test]
    fn test_rfc8439_chacha20_poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let aad = b"WireGuard Handshake AAD";
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut ct = vec![0u8; plaintext.len() + 16];
        let written = aead_encrypt(&key, 7, plaintext, aad, &mut ct);
        assert_eq!(written, plaintext.len() + 16);

        let mut pt = vec![0u8; plaintext.len()];
        let dec_len = aead_decrypt(&key, 7, &ct, aad, &mut pt).expect("AEAD decrypt should succeed");
        assert_eq!(dec_len, plaintext.len());
        assert_eq!(&pt[..], &plaintext[..]);

        // Tamper with ciphertext -> must fail authentication
        ct[10] ^= 0x01;
        assert!(aead_decrypt(&key, 7, &ct, aad, &mut pt).is_none());
    }
}
