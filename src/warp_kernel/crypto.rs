use std::time::{SystemTime, UNIX_EPOCH};

const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

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
    if last { v[14] = !v[14]; }

    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
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
    for i in 0..8 { h[i] ^= v[i] ^ v[i + 8]; }
}

fn blake2s_chunks(key: &[u8], chunks: &[&[u8]], out: &mut [u8]) {
    let mut h = BLAKE2S_IV;
    h[0] ^= 0x01010000 ^ ((key.len() as u32) << 8) ^ (out.len() as u32);
    let mut buf = [0u8; 64];
    let mut buflen = if !key.is_empty() {
        buf[..key.len()].copy_from_slice(key);
        64
    } else {
        0
    };
    let mut total = 0u64;
    for &slice in chunks {
        for &byte in slice {
            if buflen == 64 {
                total += 64;
                blake2s_compress(&mut h, &buf, total, false);
                buflen = 0;
            }
            buf[buflen] = byte;
            buflen += 1;
        }
    }
    total += buflen as u64;
    buf[buflen..64].fill(0);
    blake2s_compress(&mut h, &buf, total, true);
    let mut full = [0u8; 32];
    for (i, w) in h.iter().enumerate() {
        full[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out.copy_from_slice(&full[..out.len()]);
}

pub fn blake2s_hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    blake2s_chunks(&[], &[data], &mut out);
    out
}

pub fn blake2s_hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    blake2s_chunks(&[], &[a, b], &mut out);
    out
}

pub fn blake2s_mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    blake2s_chunks(key, &[data], &mut out);
    out
}

pub fn hmac_blake2s(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        k_pad[..32].copy_from_slice(&blake2s_hash(key));
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
    let mut b = [0u8; 33];
    b[..32].copy_from_slice(&t1);
    b[32] = 0x02;
    (t1, hmac_blake2s(&prk, &b))
}

pub fn kdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let prk = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&prk, &[0x01]);
    let mut b = [0u8; 33];
    b[..32].copy_from_slice(&t1);
    b[32] = 0x02;
    let t2 = hmac_blake2s(&prk, &b);
    b[..32].copy_from_slice(&t2);
    b[32] = 0x03;
    (t1, t2, hmac_blake2s(&prk, &b))
}

#[inline(always)]
fn chacha_qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    s[12] = counter;
    s[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    s[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    s[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
    let init = s;
    for _ in 0..10 {
        chacha_qr(&mut s, 0, 4, 8, 12); chacha_qr(&mut s, 1, 5, 9, 13);
        chacha_qr(&mut s, 2, 6, 10, 14); chacha_qr(&mut s, 3, 7, 11, 15);
        chacha_qr(&mut s, 0, 5, 10, 15); chacha_qr(&mut s, 1, 6, 11, 12);
        chacha_qr(&mut s, 2, 7, 8, 13); chacha_qr(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

fn chacha20_xor(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for chunk in data.chunks_mut(64) {
        let block = chacha20_block(key, counter, nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) { *b ^= *k; }
        counter = counter.wrapping_add(1);
    }
}

fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut rb = [0u8; 16];
    rb.copy_from_slice(&otk[0..16]);
    for &i in &[3, 7, 11, 15] { rb[i] &= 15; }
    for &i in &[4, 8, 12] { rb[i] &= 252; }
    let ru = u128::from_le_bytes(rb);
    let r = [
        (ru & 0x3ff_ffff) as u64,
        ((ru >> 26) & 0x3ff_ffff) as u64,
        ((ru >> 52) & 0x3ff_ffff) as u64,
        ((ru >> 78) & 0x3ff_ffff) as u64,
        ((ru >> 104) & 0x3ff_ffff) as u64,
    ];
    let s = [
        u32::from_le_bytes([otk[16], otk[17], otk[18], otk[19]]) as u64,
        u32::from_le_bytes([otk[20], otk[21], otk[22], otk[23]]) as u64,
        u32::from_le_bytes([otk[24], otk[25], otk[26], otk[27]]) as u64,
        u32::from_le_bytes([otk[28], otk[29], otk[30], otk[31]]) as u64,
    ];
    let mut h = [0u64; 5];

    let mut feed_block = |blk: &[u8; 16]| {
        let m = u128::from_le_bytes(*blk);
        let h0 = h[0] + ((m & 0x3ff_ffff) as u64);
        let h1 = h[1] + (((m >> 26) & 0x3ff_ffff) as u64);
        let h2 = h[2] + (((m >> 52) & 0x3ff_ffff) as u64);
        let h3 = h[3] + (((m >> 78) & 0x3ff_ffff) as u64);
        let h4 = h[4] + (((m >> 104) & 0x3ff_ffff) as u64) + (1 << 24);
        let (s1, s2, s3, s4) = (r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5);
        let d0 = h0 * r[0] + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r[1] + h1 * r[0] + h2 * s4 + h3 * s3 + h4 * s2 + (d0 >> 26);
        let d2 = h0 * r[2] + h1 * r[1] + h2 * r[0] + h3 * s4 + h4 * s3 + (d1 >> 26);
        let d3 = h0 * r[3] + h1 * r[2] + h2 * r[1] + h3 * r[0] + h4 * s4 + (d2 >> 26);
        let d4 = h0 * r[4] + h1 * r[3] + h2 * r[2] + h3 * r[1] + h4 * r[0] + (d3 >> 26);
        let mut n0 = (d0 & 0x3ff_ffff) + (d4 >> 26) * 5;
        let n1 = (d1 & 0x3ff_ffff) + (n0 >> 26);
        n0 &= 0x3ff_ffff;
        h = [n0, n1, d2 & 0x3ff_ffff, d3 & 0x3ff_ffff, d4 & 0x3ff_ffff];
    };

    for slice in [aad, ct] {
        for chunk in slice.chunks(16) {
            let mut blk = [0u8; 16];
            blk[..chunk.len()].copy_from_slice(chunk);
            feed_block(&blk);
        }
    }
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..16].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    feed_block(&lens);

    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (h[0], h[1], h[2], h[3], h[4]);
    let mut c = h1 >> 26; h1 &= 0x3ff_ffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ff_ffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ff_ffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ff_ffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ff_ffff; h1 += c;

    let mut g0 = h0.wrapping_add(5); c = g0 >> 26; g0 &= 0x3ff_ffff;
    let mut g1 = h1.wrapping_add(c); c = g1 >> 26; g1 &= 0x3ff_ffff;
    let mut g2 = h2.wrapping_add(c); c = g2 >> 26; g2 &= 0x3ff_ffff;
    let mut g3 = h3.wrapping_add(c); c = g3 >> 26; g3 &= 0x3ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    let inv = !mask;
    h0 = (h0 & inv) | (g0 & mask);
    h1 = (h1 & inv) | (g1 & mask);
    h2 = (h2 & inv) | (g2 & mask);
    h3 = (h3 & inv) | (g3 & mask);
    h4 = (h4 & inv) | (g4 & mask);

    let w = [
        (h0 | (h1 << 26)) & 0xffff_ffff,
        ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff,
        ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff,
        ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff,
    ];
    let mut f = 0u64;
    let mut tag = [0u8; 16];
    for i in 0..4 {
        f = w[i] + s[i] + (f >> 32);
        tag[i * 4..i * 4 + 4].copy_from_slice(&(f as u32).to_le_bytes());
    }
    tag
}

pub fn aead_encrypt(key: &[u8; 32], counter: u64, pt: &[u8], aad: &[u8], out: &mut [u8]) -> usize {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    let b0 = chacha20_block(key, 0, &nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&b0[0..32]);
    let n = pt.len();
    out[..n].copy_from_slice(pt);
    chacha20_xor(key, 1, &nonce, &mut out[..n]);
    let tag = poly1305_aead_tag(&otk, aad, &out[..n]);
    out[n..n + 16].copy_from_slice(&tag);
    n + 16
}

pub fn aead_decrypt(key: &[u8; 32], counter: u64, ct_tag: &[u8], aad: &[u8], out: &mut [u8]) -> Option<usize> {
    if ct_tag.len() < 16 { return None; }
    let n = ct_tag.len() - 16;
    if out.len() < n { return None; }
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    let b0 = chacha20_block(key, 0, &nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&b0[0..32]);
    let expected = poly1305_aead_tag(&otk, aad, &ct_tag[..n]);
    let mut diff = 0u8;
    for i in 0..16 { diff |= expected[i] ^ ct_tag[n + i]; }
    if diff != 0 { return None; }
    out[..n].copy_from_slice(&ct_tag[..n]);
    chacha20_xor(key, 1, &nonce, &mut out[..n]);
    Some(n)
}

pub fn tai64n_now() -> [u8; 12] {
    static LAST_TS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = 0x4000_0000_0000_000au64.wrapping_add(dur.as_secs());
    let nanos = (dur.subsec_nanos() & 0xffff_ff00) as u64;
    let packed = (secs << 20) | (nanos >> 12);
    let prev = LAST_TS.fetch_max(packed, std::sync::atomic::Ordering::SeqCst);
    let final_secs = if packed <= prev { secs.wrapping_add(1) } else { secs };
    let mut out = [0u8; 12];
    out[0..8].copy_from_slice(&final_secs.to_be_bytes());
    out[8..12].copy_from_slice(&(nanos as u32).to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2s_and_chacha20poly1305() {
        assert_eq!(blake2s_hash(b"abc"), blake2s_hash2(b"a", b"bc"));
        let key = [0x42u8; 32];
        let pt = b"WireGuard ChaCha20Poly1305 payload";
        let mut ct = [0u8; 50];
        let len = aead_encrypt(&key, 7, pt, b"aad", &mut ct);
        let mut dec = [0u8; 34];
        assert_eq!(aead_decrypt(&key, 7, &ct[..len], b"aad", &mut dec), Some(pt.len()));
        assert_eq!(&dec[..], pt);
        ct[0] ^= 1;
        assert!(aead_decrypt(&key, 7, &ct[..len], b"aad", &mut dec).is_none());
    }
}
