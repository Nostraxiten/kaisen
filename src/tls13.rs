//! A minimal TLS 1.3 client, written from scratch like the rest of Kaisen.
//!
//! This exists so `+dot` and `--doh` can send a DNS query down an encrypted
//! channel. It is deliberately the smallest client that can hold a real TLS 1.3
//! conversation:
//!
//!   * key exchange: X25519 only
//!   * cipher suites: ChaCha20-Poly1305 and AES-128-GCM, both with SHA-256
//!   * no session resumption, no 0-RTT, no client certificates, no renegotiation
//!
//! `tls.rs` is the *passive* prober used by `-sV`: it sends a ClientHello and
//! reads whatever comes back in the clear, and never completes a handshake.
//! This module completes one. The two coexist on purpose — the prober must stay
//! cheap and must not care whether the peer is trustworthy, while this one has
//! to derive keys and encrypt.
//!
//! # What is verified, and what is not
//!
//! The server certificate's names and validity dates are checked: a wrong
//! hostname or an expired certificate fails the connection. The **signature
//! chain is not validated** against a trust store — that needs RSA and ECDSA
//! verification plus a bundled root store, which this does not carry yet. So
//! the channel defeats a passive eavesdropper but not an active
//! man-in-the-middle. Kaisen says this out loud when you use it rather than
//! implying a guarantee it cannot make; see `TlsSession::trust_note`.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ════════════════════════════════════════════════════════════════════════════
// SHA-256 (FIPS 180-4)
// ════════════════════════════════════════════════════════════════════════════

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buflen: usize,
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buflen: 0,
            total: 0,
        }
    }

    fn compress(&mut self, block: &[u8]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let add = [a, b, c, d, e, f, g, h];
        for (s, v) in self.state.iter_mut().zip(add.iter()) {
            *s = s.wrapping_add(*v);
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            self.compress(block);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        // update() just bumped `total`; the length field must describe the
        // message, so it was captured before padding started.
        while self.buflen != 56 {
            self.update(&[0x00]);
        }
        let mut block = self.buf;
        block[56..64].copy_from_slice(&bits.to_be_bytes());
        self.compress(&block);
        let mut out = [0u8; 32];
        for (i, v) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

// ════════════════════════════════════════════════════════════════════════════
// HMAC-SHA256 and HKDF (RFC 5869), with TLS 1.3's labelled form (RFC 8446 §7.1)
// ════════════════════════════════════════════════════════════════════════════

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finish();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finish()
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        let block = hmac_sha256(prk, &msg);
        t = block.to_vec();
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// HKDF-Expand-Label: the TLS 1.3 wrapper that puts a structured, "tls13 "
/// prefixed label into the HKDF info field so two different derivations can
/// never collide.
pub fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

pub fn derive_secret(secret: &[u8], label: &str, transcript_hash: &[u8]) -> [u8; 32] {
    let v = hkdf_expand_label(secret, label, transcript_hash, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

// ════════════════════════════════════════════════════════════════════════════
// X25519 (RFC 7748)
//
// Field elements are five 51-bit limbs, little-endian: the standard radix for
// 64-bit machines, where a limb product stays inside a u128.
// ════════════════════════════════════════════════════════════════════════════

type Fe = [u64; 5];

const LIMB_MASK: u64 = (1u64 << 51) - 1;

const FE_ZERO: Fe = [0, 0, 0, 0, 0];
const FE_ONE: Fe = [1, 0, 0, 0, 0];

fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let load = |i: usize| -> u64 {
        let mut v = [0u8; 8];
        v.copy_from_slice(&b[i..i + 8]);
        u64::from_le_bytes(v)
    };
    [
        load(0) & LIMB_MASK,
        (load(6) >> 3) & LIMB_MASK,
        (load(12) >> 6) & LIMB_MASK,
        (load(19) >> 1) & LIMB_MASK,
        // Masking here also clears bit 255, which RFC 7748 says to ignore.
        (load(24) >> 12) & LIMB_MASK,
    ]
}

/// Carry-propagate so every limb is below 2^51.
fn fe_reduce(f: &Fe) -> Fe {
    let mut t = *f;
    t[1] += t[0] >> 51;
    t[0] &= LIMB_MASK;
    t[2] += t[1] >> 51;
    t[1] &= LIMB_MASK;
    t[3] += t[2] >> 51;
    t[2] &= LIMB_MASK;
    t[4] += t[3] >> 51;
    t[3] &= LIMB_MASK;
    t[0] += 19 * (t[4] >> 51);
    t[4] &= LIMB_MASK;
    t[1] += t[0] >> 51;
    t[0] &= LIMB_MASK;
    t
}

fn fe_to_bytes(f: &Fe) -> [u8; 32] {
    let mut t = fe_reduce(f);
    // Conditional subtraction of p = 2^255 - 19, done by adding 19 and looking
    // at whether that carries out of bit 255.
    let mut q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;
    t[0] += 19 * q;
    t[1] += t[0] >> 51;
    t[0] &= LIMB_MASK;
    t[2] += t[1] >> 51;
    t[1] &= LIMB_MASK;
    t[3] += t[2] >> 51;
    t[2] &= LIMB_MASK;
    t[4] += t[3] >> 51;
    t[3] &= LIMB_MASK;
    t[4] &= LIMB_MASK;

    let mut out = [0u8; 32];
    let words = [
        t[0] | (t[1] << 51),
        (t[1] >> 13) | (t[2] << 38),
        (t[2] >> 26) | (t[3] << 25),
        (t[3] >> 39) | (t[4] << 12),
    ];
    for (i, w) in words.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn fe_mul(f: &Fe, g: &Fe) -> Fe {
    let a: [u128; 5] = [
        f[0] as u128,
        f[1] as u128,
        f[2] as u128,
        f[3] as u128,
        f[4] as u128,
    ];
    let b: [u128; 5] = [
        g[0] as u128,
        g[1] as u128,
        g[2] as u128,
        g[3] as u128,
        g[4] as u128,
    ];
    // Limbs that wrap past 2^255 come back multiplied by 19, since
    // 2^255 = 19 (mod p).
    let b19: [u128; 5] = [b[0], b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];

    let mut h = [
        a[0] * b[0] + a[1] * b19[4] + a[2] * b19[3] + a[3] * b19[2] + a[4] * b19[1],
        a[0] * b[1] + a[1] * b[0] + a[2] * b19[4] + a[3] * b19[3] + a[4] * b19[2],
        a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b19[4] + a[4] * b19[3],
        a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b19[4],
        a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
    ];

    const M: u128 = (1u128 << 51) - 1;
    h[1] += h[0] >> 51;
    h[0] &= M;
    h[2] += h[1] >> 51;
    h[1] &= M;
    h[3] += h[2] >> 51;
    h[2] &= M;
    h[4] += h[3] >> 51;
    h[3] &= M;
    h[0] += 19 * (h[4] >> 51);
    h[4] &= M;
    h[1] += h[0] >> 51;
    h[0] &= M;

    [h[0] as u64, h[1] as u64, h[2] as u64, h[3] as u64, h[4] as u64]
}

fn fe_sq(f: &Fe) -> Fe {
    fe_mul(f, f)
}

fn fe_add(f: &Fe, g: &Fe) -> Fe {
    [
        f[0] + g[0],
        f[1] + g[1],
        f[2] + g[2],
        f[3] + g[3],
        f[4] + g[4],
    ]
}

fn fe_sub(f: &Fe, g: &Fe) -> Fe {
    // Add 2p before subtracting so no limb can go negative. Both operands are
    // reduced first, which keeps every limb below 2^51 and therefore below the
    // 2p constants.
    let f = fe_reduce(f);
    let g = fe_reduce(g);
    const TWO_P0: u64 = 0x0FFFFFFFFFFFDA; // 2 * (2^51 - 19)
    const TWO_P: u64 = 0x0FFFFFFFFFFFFE; // 2 * (2^51 - 1)
    fe_reduce(&[
        f[0] + TWO_P0 - g[0],
        f[1] + TWO_P - g[1],
        f[2] + TWO_P - g[2],
        f[3] + TWO_P - g[3],
        f[4] + TWO_P - g[4],
    ])
}

fn fe_mul121666(f: &Fe) -> Fe {
    let mut h = [
        f[0] as u128 * 121666,
        f[1] as u128 * 121666,
        f[2] as u128 * 121666,
        f[3] as u128 * 121666,
        f[4] as u128 * 121666,
    ];
    const M: u128 = (1u128 << 51) - 1;
    h[1] += h[0] >> 51;
    h[0] &= M;
    h[2] += h[1] >> 51;
    h[1] &= M;
    h[3] += h[2] >> 51;
    h[2] &= M;
    h[4] += h[3] >> 51;
    h[3] &= M;
    h[0] += 19 * (h[4] >> 51);
    h[4] &= M;
    [h[0] as u64, h[1] as u64, h[2] as u64, h[3] as u64, h[4] as u64]
}

/// Swap `a` and `b` when `swap` is 1, using arithmetic rather than a branch so
/// the scalar bit never steers control flow.
fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// f^(p-2) mod p, which is the inverse. The addition chain is the standard one
/// from the reference implementation.
fn fe_invert(f: &Fe) -> Fe {
    let z1 = *f;
    let z2 = fe_sq(&z1);
    let z8 = fe_sq(&fe_sq(&z2));
    let z9 = fe_mul(&z8, &z1);
    let z11 = fe_mul(&z9, &z2);
    let z22 = fe_sq(&z11);
    let z_5_0 = fe_mul(&z22, &z9);

    let mut t = fe_sq(&z_5_0);
    for _ in 1..5 {
        t = fe_sq(&t);
    }
    let z_10_0 = fe_mul(&t, &z_5_0);

    let mut t = fe_sq(&z_10_0);
    for _ in 1..10 {
        t = fe_sq(&t);
    }
    let z_20_0 = fe_mul(&t, &z_10_0);

    let mut t = fe_sq(&z_20_0);
    for _ in 1..20 {
        t = fe_sq(&t);
    }
    let z_40_0 = fe_mul(&t, &z_20_0);

    let mut t = fe_sq(&z_40_0);
    for _ in 1..10 {
        t = fe_sq(&t);
    }
    let z_50_0 = fe_mul(&t, &z_10_0);

    let mut t = fe_sq(&z_50_0);
    for _ in 1..50 {
        t = fe_sq(&t);
    }
    let z_100_0 = fe_mul(&t, &z_50_0);

    let mut t = fe_sq(&z_100_0);
    for _ in 1..100 {
        t = fe_sq(&t);
    }
    let z_200_0 = fe_mul(&t, &z_100_0);

    let mut t = fe_sq(&z_200_0);
    for _ in 1..50 {
        t = fe_sq(&t);
    }
    let z_250_0 = fe_mul(&t, &z_50_0);

    let mut t = fe_sq(&z_250_0);
    for _ in 1..5 {
        t = fe_sq(&t);
    }
    fe_mul(&t, &z11)
}

/// The X25519 function: scalar multiplication on Curve25519 via the Montgomery
/// ladder, which touches both branches on every bit.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut e = *scalar;
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    let x1 = fe_from_bytes(point);
    let mut x2 = FE_ONE;
    let mut z2 = FE_ZERO;
    let mut x3 = x1;
    let mut z3 = FE_ONE;
    let mut swap = 0u64;

    for pos in (0..255).rev() {
        let bit = ((e[pos >> 3] >> (pos & 7)) & 1) as u64;
        swap ^= bit;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = fe_add(&x2, &z2);
        let b = fe_sub(&x2, &z2);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        let aa = fe_sq(&a);
        let bb = fe_sq(&b);

        x3 = fe_sq(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        let e_ = fe_sub(&aa, &bb);
        z2 = fe_mul(&e_, &fe_add(&bb, &fe_mul121666(&e_)));
    }
    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    fe_to_bytes(&fe_mul(&x2, &fe_invert(&z2)))
}

const X25519_BASE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    x25519(scalar, &X25519_BASE)
}

// ════════════════════════════════════════════════════════════════════════════
// ChaCha20-Poly1305 (RFC 8439)
// ════════════════════════════════════════════════════════════════════════════

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let mut w = state;
    macro_rules! qr {
        ($s:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
            $s[$a] = $s[$a].wrapping_add($s[$b]);
            $s[$d] = ($s[$d] ^ $s[$a]).rotate_left(16);
            $s[$c] = $s[$c].wrapping_add($s[$d]);
            $s[$b] = ($s[$b] ^ $s[$c]).rotate_left(12);
            $s[$a] = $s[$a].wrapping_add($s[$b]);
            $s[$d] = ($s[$d] ^ $s[$a]).rotate_left(8);
            $s[$c] = $s[$c].wrapping_add($s[$d]);
            $s[$b] = ($s[$b] ^ $s[$c]).rotate_left(7);
        };
    }
    for _ in 0..10 {
        qr!(w, 0, 4, 8, 12);
        qr!(w, 1, 5, 9, 13);
        qr!(w, 2, 6, 10, 14);
        qr!(w, 3, 7, 11, 15);
        qr!(w, 0, 5, 10, 15);
        qr!(w, 1, 6, 11, 12);
        qr!(w, 2, 7, 8, 13);
        qr!(w, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&w[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let ks = chacha20_block(key, counter + i as u32, nonce);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }
    }
}

/// Poly1305 one-time authenticator, in 130-bit arithmetic carried in u64 limbs.
fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // r is clamped as the spec requires, then held as five 26-bit limbs.
    let mut r = [0u32; 5];
    let mut s = [0u32; 4];
    let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
    let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
    let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
    let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
    r[0] = t0 & 0x3ffffff;
    r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    r[4] = (t3 >> 8) & 0x00fffff;
    for i in 0..4 {
        s[i] = u32::from_le_bytes([
            key[16 + i * 4],
            key[17 + i * 4],
            key[18 + i * 4],
            key[19 + i * 4],
        ]);
    }

    let mut h = [0u32; 5];
    for chunk in msg.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1; // the high bit that terminates each block
        let b0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let b1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let b2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let b3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);
        let b4 = block[16] as u32;

        h[0] += b0 & 0x3ffffff;
        h[1] += ((b0 >> 26) | (b1 << 6)) & 0x3ffffff;
        h[2] += ((b1 >> 20) | (b2 << 12)) & 0x3ffffff;
        h[3] += ((b2 >> 14) | (b3 << 18)) & 0x3ffffff;
        h[4] += (b3 >> 8) | (b4 << 24);

        // h *= r (mod 2^130 - 5)
        let s1 = (r[1] as u64) * 5;
        let s2 = (r[2] as u64) * 5;
        let s3 = (r[3] as u64) * 5;
        let s4 = (r[4] as u64) * 5;
        let h0 = h[0] as u64;
        let h1 = h[1] as u64;
        let h2 = h[2] as u64;
        let h3 = h[3] as u64;
        let h4 = h[4] as u64;
        let r0 = r[0] as u64;
        let r1 = r[1] as u64;
        let r2 = r[2] as u64;
        let r3 = r[3] as u64;
        let r4 = r[4] as u64;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h[0] = (d0 & 0x3ffffff) as u32;
        let d1 = d1 + c;
        c = d1 >> 26;
        h[1] = (d1 & 0x3ffffff) as u32;
        let d2 = d2 + c;
        c = d2 >> 26;
        h[2] = (d2 & 0x3ffffff) as u32;
        let d3 = d3 + c;
        c = d3 >> 26;
        h[3] = (d3 & 0x3ffffff) as u32;
        let d4 = d4 + c;
        c = d4 >> 26;
        h[4] = (d4 & 0x3ffffff) as u32;
        h[0] += (c as u32) * 5;
        let c = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += c;
    }

    // Final carry propagation.
    let mut c = h[1] >> 26;
    h[1] &= 0x3ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x3ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x3ffffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;

    // Compute h + -p and pick it if it did not borrow.
    let mut g = [0u32; 5];
    let mut c = 0u32;
    for i in 0..5 {
        let mut v = h[i].wrapping_add(c);
        if i == 0 {
            v = h[i] + 5;
        }
        c = v >> 26;
        g[i] = v & 0x3ffffff;
    }
    g[4] = g[4].wrapping_sub(1 << 26);

    let mask = (g[4] >> 31).wrapping_sub(1); // all ones when g >= 0
    for i in 0..5 {
        h[i] = (h[i] & !mask) | (g[i] & mask);
    }

    // Serialise as four 32-bit words plus the key's s value.
    let h0 = (h[0] | (h[1] << 26)) as u64;
    let h1 = ((h[1] >> 6) | (h[2] << 20)) as u64;
    let h2 = ((h[2] >> 12) | (h[3] << 14)) as u64;
    let h3 = ((h[3] >> 18) | (h[4] << 8)) as u64;

    let mut acc = [0u32; 4];
    let mut carry = 0u64;
    for (i, hv) in [h0, h1, h2, h3].iter().enumerate() {
        let v = (*hv & 0xffffffff) + s[i] as u64 + carry;
        acc[i] = (v & 0xffffffff) as u32;
        carry = v >> 32;
    }

    let mut tag = [0u8; 16];
    for i in 0..4 {
        tag[i * 4..i * 4 + 4].copy_from_slice(&acc[i].to_le_bytes());
    }
    tag
}

fn poly1305_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    let mut k = [0u8; 32];
    k.copy_from_slice(&block[..32]);
    k
}

fn poly1305_input(aad: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(aad.len() + ct.len() + 32);
    m.extend_from_slice(aad);
    m.resize(m.len() + ((16 - aad.len() % 16) % 16), 0);
    m.extend_from_slice(ct);
    m.resize(m.len() + ((16 - ct.len() % 16) % 16), 0);
    m.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    m.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    m
}

fn chacha20poly1305_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut ct = plain.to_vec();
    chacha20_xor(key, 1, nonce, &mut ct);
    let tag = poly1305(&poly1305_key(key, nonce), &poly1305_input(aad, &ct));
    ct.extend_from_slice(&tag);
    ct
}

fn chacha20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    if sealed.len() < 16 {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let want = poly1305(&poly1305_key(key, nonce), &poly1305_input(aad, ct));
    if !ct_eq(&want, tag) {
        return None;
    }
    let mut plain = ct.to_vec();
    chacha20_xor(key, 1, nonce, &mut plain);
    Some(plain)
}

/// Compare without an early exit, so a wrong tag reveals nothing through timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ════════════════════════════════════════════════════════════════════════════
// AES-128-GCM — the mandatory-to-implement TLS 1.3 suite, kept as the fallback
// for servers that will not negotiate ChaCha20.
// ════════════════════════════════════════════════════════════════════════════

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0x00 }
}

/// AES-128 key schedule: 11 round keys of 16 bytes.
fn aes128_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [[0u8; 16]; 11];
    w[0].copy_from_slice(key);
    let mut rcon = 1u8;
    for r in 1..11 {
        let prev = w[r - 1];
        let mut t = [prev[13], prev[14], prev[15], prev[12]];
        for b in t.iter_mut() {
            *b = AES_SBOX[*b as usize];
        }
        t[0] ^= rcon;
        rcon = xtime(rcon);
        for i in 0..4 {
            w[r][i] = prev[i] ^ t[i];
        }
        for i in 4..16 {
            w[r][i] = prev[i] ^ w[r][i - 4];
        }
    }
    w
}

fn aes128_encrypt_block(rk: &[[u8; 16]; 11], block: &[u8; 16]) -> [u8; 16] {
    let mut s = *block;
    for (i, b) in s.iter_mut().enumerate() {
        *b ^= rk[0][i];
    }
    for (round, rkey) in rk.iter().enumerate().skip(1) {
        // SubBytes
        for b in s.iter_mut() {
            *b = AES_SBOX[*b as usize];
        }
        // ShiftRows (state is column-major: byte i is row i%4, column i/4)
        let t = s;
        for c in 0..4 {
            for r in 0..4 {
                s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
            }
        }
        // MixColumns, skipped in the final round
        if round != 10 {
            for c in 0..4 {
                let col = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
                s[c * 4] = xtime(col[0]) ^ (xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3];
                s[c * 4 + 1] = col[0] ^ xtime(col[1]) ^ (xtime(col[2]) ^ col[2]) ^ col[3];
                s[c * 4 + 2] = col[0] ^ col[1] ^ xtime(col[2]) ^ (xtime(col[3]) ^ col[3]);
                s[c * 4 + 3] = (xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime(col[3]);
            }
        }
        for (b, k) in s.iter_mut().zip(rkey.iter()) {
            *b ^= *k;
        }
    }
    s
}

/// Multiplication in GF(2^128) with GCM's bit ordering.
fn ghash_mul(x: &mut [u8; 16], h: &[u8; 16]) {
    let mut z = [0u8; 16];
    let mut v = *h;
    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        if bit == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        let lsb = v[15] & 1;
        // v >>= 1
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;
        if lsb == 1 {
            v[0] ^= 0xe1;
        }
    }
    *x = z;
}

fn ghash(h: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    let feed = |data: &[u8], y: &mut [u8; 16]| {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..16 {
                y[i] ^= block[i];
            }
            ghash_mul(y, h);
        }
    };
    feed(aad, &mut y);
    feed(ct, &mut y);
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    for i in 0..16 {
        y[i] ^= len_block[i];
    }
    ghash_mul(&mut y, h);
    y
}

fn aes_gcm_ctr(rk: &[[u8; 16]; 11], nonce: &[u8; 12], start: u32, data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(16).enumerate() {
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);
        counter[12..].copy_from_slice(&(start + i as u32).to_be_bytes());
        let ks = aes128_encrypt_block(rk, &counter);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }
    }
}

fn aes128gcm_seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let rk = aes128_expand(key);
    let h = aes128_encrypt_block(&rk, &[0u8; 16]);
    let mut ct = plain.to_vec();
    aes_gcm_ctr(&rk, nonce, 2, &mut ct);
    let mut tag = ghash(&h, aad, &ct);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let s = aes128_encrypt_block(&rk, &j0);
    for i in 0..16 {
        tag[i] ^= s[i];
    }
    ct.extend_from_slice(&tag);
    ct
}

fn aes128gcm_open(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 16 {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let rk = aes128_expand(key);
    let h = aes128_encrypt_block(&rk, &[0u8; 16]);
    let mut want = ghash(&h, aad, ct);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let s = aes128_encrypt_block(&rk, &j0);
    for i in 0..16 {
        want[i] ^= s[i];
    }
    if !ct_eq(&want, tag) {
        return None;
    }
    let mut plain = ct.to_vec();
    aes_gcm_ctr(&rk, nonce, 2, &mut plain);
    Some(plain)
}

// ════════════════════════════════════════════════════════════════════════════
// AEAD selection
// ════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    ChaCha20Poly1305,
    Aes128Gcm,
}

impl Suite {
    fn from_id(id: u16) -> Option<Suite> {
        match id {
            0x1303 => Some(Suite::ChaCha20Poly1305),
            0x1301 => Some(Suite::Aes128Gcm),
            _ => None,
        }
    }
    fn key_len(&self) -> usize {
        match self {
            Suite::ChaCha20Poly1305 => 32,
            Suite::Aes128Gcm => 16,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Suite::ChaCha20Poly1305 => "TLS_CHACHA20_POLY1305_SHA256",
            Suite::Aes128Gcm => "TLS_AES_128_GCM_SHA256",
        }
    }
    fn seal(&self, key: &[u8], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
        match self {
            Suite::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                chacha20poly1305_seal(&k, nonce, aad, plain)
            }
            Suite::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                aes128gcm_seal(&k, nonce, aad, plain)
            }
        }
    }
    fn open(&self, key: &[u8], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        match self {
            Suite::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                chacha20poly1305_open(&k, nonce, aad, sealed)
            }
            Suite::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                aes128gcm_open(&k, nonce, aad, sealed)
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Key schedule (RFC 8446 §7.1)
// ════════════════════════════════════════════════════════════════════════════

/// The four secrets a full handshake produces, in the order they are derived.
struct KeySchedule {
    handshake_secret: [u8; 32],
    client_hs: [u8; 32],
    server_hs: [u8; 32],
}

impl KeySchedule {
    fn new(shared: &[u8; 32], transcript_hash: &[u8]) -> KeySchedule {
        let zeros = [0u8; 32];
        let early = hkdf_extract(&zeros, &zeros);
        let derived = derive_secret(&early, "derived", &sha256(b""));
        let handshake_secret = hkdf_extract(&derived, shared);
        KeySchedule {
            client_hs: derive_secret(&handshake_secret, "c hs traffic", transcript_hash),
            server_hs: derive_secret(&handshake_secret, "s hs traffic", transcript_hash),
            handshake_secret,
        }
    }

    /// Application traffic secrets, derived once the server's Finished has been
    /// folded into the transcript.
    fn application(&self, transcript_hash: &[u8]) -> ([u8; 32], [u8; 32]) {
        let zeros = [0u8; 32];
        let derived = derive_secret(&self.handshake_secret, "derived", &sha256(b""));
        let master = hkdf_extract(&derived, &zeros);
        (
            derive_secret(&master, "c ap traffic", transcript_hash),
            derive_secret(&master, "s ap traffic", transcript_hash),
        )
    }
}

/// One direction's record-protection state: a key, a base IV and a sequence
/// number that is XORed into the IV to form each record's nonce.
struct Keys {
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl Keys {
    fn from_secret(secret: &[u8; 32], suite: Suite) -> Keys {
        let key = hkdf_expand_label(secret, "key", b"", suite.key_len());
        let iv_v = hkdf_expand_label(secret, "iv", b"", 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_v);
        Keys { key, iv, seq: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let seq = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= seq[i];
        }
        n
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Randomness
// ════════════════════════════════════════════════════════════════════════════

/// Key material comes from the OS and nowhere else. `tls.rs` has a cheap
/// clock-seeded PRNG that is fine for a probe's ClientHello random, but a
/// private key drawn from a predictable stream is not a private key at all —
/// so this fails loudly rather than falling back to something weaker.
fn os_random(n: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("no secure randomness available (/dev/urandom): {e}"))?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)
        .map_err(|e| format!("could not read /dev/urandom: {e}"))?;
    Ok(buf)
}

// ════════════════════════════════════════════════════════════════════════════
// Handshake
// ════════════════════════════════════════════════════════════════════════════

const REC_CHANGE_CIPHER_SPEC: u8 = 20;
const REC_ALERT: u8 = 21;
const REC_HANDSHAKE: u8 = 22;
const REC_APPLICATION: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

/// The magic ServerHello random that marks a HelloRetryRequest (RFC 8446 §4.1.3).
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

fn u16b(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn ext(id: u16, body: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&u16b(id));
    out.extend_from_slice(&u16b(body.len() as u16));
    out.extend_from_slice(body);
}

/// Is this a DNS name rather than an IP literal? SNI must not carry an address.
fn is_dns_name(h: &str) -> bool {
    !h.is_empty()
        && h.parse::<std::net::IpAddr>().is_err()
        && h.contains('.')
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

fn client_hello(host: &str, pubkey: &[u8; 32], random: &[u8], session_id: &[u8], alpn: &[&str]) -> Vec<u8> {
    let mut exts: Vec<u8> = Vec::new();

    if is_dns_name(host) {
        let name = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&u16b(name.len() as u16 + 3));
        sni.push(0); // host_name
        sni.extend_from_slice(&u16b(name.len() as u16));
        sni.extend_from_slice(name);
        ext(0, &sni, &mut exts);
    }

    // supported_groups: x25519 only, which is what this client can compute.
    ext(10, &[0x00, 0x02, 0x00, 0x1d], &mut exts);
    // ec_point_formats: uncompressed, for middleboxes that still look.
    ext(11, &[0x01, 0x00], &mut exts);

    // signature_algorithms. We do not verify signatures, but the extension is
    // mandatory and the list steers the server toward a common certificate.
    let sigalgs: [u16; 9] = [
        0x0403, 0x0503, 0x0603, // ECDSA P-256/384/521 + SHA-2
        0x0804, 0x0805, 0x0806, // RSA-PSS
        0x0807, // Ed25519
        0x0401, 0x0501, // RSA PKCS#1
    ];
    let mut sa = Vec::new();
    sa.extend_from_slice(&u16b(sigalgs.len() as u16 * 2));
    for a in sigalgs {
        sa.extend_from_slice(&u16b(a));
    }
    ext(13, &sa, &mut exts);

    if !alpn.is_empty() {
        let mut list = Vec::new();
        for p in alpn {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        let mut body = Vec::new();
        body.extend_from_slice(&u16b(list.len() as u16));
        body.extend_from_slice(&list);
        ext(16, &body, &mut exts);
    }

    // supported_versions: TLS 1.3 only. Offering 1.2 as well would invite a
    // downgrade this client cannot speak.
    ext(43, &[0x02, 0x03, 0x04], &mut exts);
    // psk_key_exchange_modes: psk_dhe_ke, required by some stacks even without PSK.
    ext(45, &[0x01, 0x01], &mut exts);

    // key_share with our X25519 public key.
    let mut ks = Vec::new();
    ks.extend_from_slice(&u16b(36)); // one entry: group(2) + len(2) + 32
    ks.extend_from_slice(&u16b(0x001d));
    ks.extend_from_slice(&u16b(32));
    ks.extend_from_slice(pubkey);
    ext(51, &ks, &mut exts);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    // cipher_suites, best first.
    body.extend_from_slice(&u16b(4));
    body.extend_from_slice(&u16b(0x1303)); // ChaCha20-Poly1305
    body.extend_from_slice(&u16b(0x1301)); // AES-128-GCM
    body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods: null
    body.extend_from_slice(&u16b(exts.len() as u16));
    body.extend_from_slice(&exts);

    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(HS_CLIENT_HELLO);
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    hs
}

/// An established TLS 1.3 connection, ready to carry application data.
pub struct TlsSession {
    stream: TcpStream,
    suite: Suite,
    client: Keys,
    server: Keys,
    /// Raw bytes read from the socket that do not yet form a whole record.
    inbuf: Vec<u8>,
    /// Decrypted application data not yet handed to the caller.
    plain: Vec<u8>,
    pub alpn: Option<String>,
    /// What could be said about the peer's certificate — names, expiry, and the
    /// standing caveat that the chain itself was not verified.
    pub cert_summary: String,
    pub cert_trusted_names: bool,
}

impl TlsSession {
    /// The honest one-line statement of what this channel does and does not
    /// guarantee, for printing next to results obtained through it. It changes
    /// with what was actually checkable: against an IP literal there is no name
    /// to match, and saying otherwise would overstate the guarantee.
    pub fn trust_note(&self) -> &'static str {
        if self.cert_trusted_names {
            "encrypted; certificate name and dates checked, issuer chain NOT verified \
             (protects against eavesdropping, not against an active attacker)"
        } else {
            "encrypted; certificate dates checked but no name to match against an IP, \
             issuer chain NOT verified (protects against eavesdropping, not against \
             an active attacker)"
        }
    }

    /// The protocol the peer agreed to over ALPN, when one was offered.
    pub fn alpn_name(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    pub fn suite_name(&self) -> &'static str {
        self.suite.name()
    }
}

fn hostname_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = pattern.strip_prefix("*.") {
        // A wildcard covers exactly one label, so a.b.example.com does not
        // match *.example.com.
        return match host.split_once('.') {
            Some((_, tail)) => tail == rest,
            None => false,
        };
    }
    pattern == host
}

async fn read_more(stream: &mut TcpStream, buf: &mut Vec<u8>, dur: Duration) -> Result<(), String> {
    let mut chunk = [0u8; 8192];
    let n = timeout(dur, stream.read(&mut chunk))
        .await
        .map_err(|_| "TLS read timed out".to_string())?
        .map_err(|e| format!("TLS read failed: {e}"))?;
    if n == 0 {
        return Err("server closed the connection during the handshake".into());
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

/// Pull one whole record out of `buf`, reading more from the socket as needed.
/// Returns (content_type, payload).
async fn next_record(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    dur: Duration,
) -> Result<(u8, Vec<u8>), String> {
    loop {
        if buf.len() >= 5 {
            let len = ((buf[3] as usize) << 8) | buf[4] as usize;
            if len > 16640 {
                return Err("TLS record too large".into());
            }
            if buf.len() >= 5 + len {
                let ctype = buf[0];
                let payload = buf[5..5 + len].to_vec();
                buf.drain(..5 + len);
                return Ok((ctype, payload));
            }
        }
        read_more(stream, buf, dur).await?;
    }
}

fn alert_text(payload: &[u8]) -> String {
    if payload.len() < 2 {
        return "TLS alert".into();
    }
    let desc = match payload[1] {
        0 => "close_notify",
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        112 => "unrecognized_name",
        120 => "no_application_protocol",
        _ => "unknown",
    };
    format!("server sent a TLS alert: {desc}")
}

/// Decrypt one application_data record and strip TLS 1.3's inner padding,
/// returning (real_content_type, plaintext).
fn decrypt_record(suite: Suite, keys: &mut Keys, header: &[u8], body: &[u8]) -> Result<(u8, Vec<u8>), String> {
    let nonce = keys.nonce();
    keys.seq += 1;
    let mut inner = suite
        .open(&keys.key, &nonce, header, body)
        .ok_or_else(|| "TLS record failed authentication".to_string())?;
    // The content type is the last non-zero byte; everything after it is padding.
    while inner.last() == Some(&0) {
        inner.pop();
    }
    let ctype = inner.pop().ok_or("empty TLS inner plaintext")?;
    Ok((ctype, inner))
}

fn encrypt_record(suite: Suite, keys: &mut Keys, ctype: u8, plain: &[u8]) -> Vec<u8> {
    let mut inner = plain.to_vec();
    inner.push(ctype);
    let total = inner.len() + 16; // AEAD tag
    let mut header = Vec::with_capacity(5);
    header.push(REC_APPLICATION);
    header.extend_from_slice(&[0x03, 0x03]);
    header.extend_from_slice(&u16b(total as u16));
    let nonce = keys.nonce();
    keys.seq += 1;
    let sealed = suite.seal(&keys.key, &nonce, &header, &inner);
    let mut out = header;
    out.extend_from_slice(&sealed);
    out
}

/// Complete a TLS 1.3 handshake over an already-connected socket.
///
/// `host` is used for SNI and for checking the certificate's names. `alpn` is
/// the protocol list to offer; pass an empty slice to omit the extension.
pub async fn handshake(
    mut stream: TcpStream,
    host: &str,
    alpn: &[&str],
    timeout_ms: u64,
) -> Result<TlsSession, String> {
    let dur = Duration::from_millis(timeout_ms.max(2000));

    // ── ClientHello ────────────────────────────────────────────────────────
    let secret_bytes = os_random(32)?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);
    let pubkey = x25519_base(&secret);
    let random = os_random(32)?;
    let session_id = os_random(32)?;

    let ch = client_hello(host, &pubkey, &random, &session_id, alpn);
    let mut transcript = Sha256::new();
    transcript.update(&ch);

    let mut rec = Vec::with_capacity(ch.len() + 5);
    rec.push(REC_HANDSHAKE);
    rec.extend_from_slice(&[0x03, 0x01]); // legacy record version for the first flight
    rec.extend_from_slice(&u16b(ch.len() as u16));
    rec.extend_from_slice(&ch);
    timeout(dur, stream.write_all(&rec))
        .await
        .map_err(|_| "TLS write timed out".to_string())?
        .map_err(|e| format!("TLS write failed: {e}"))?;

    // ── ServerHello ────────────────────────────────────────────────────────
    let mut inbuf: Vec<u8> = Vec::new();
    let (suite, server_pub) = loop {
        let (ctype, payload) = next_record(&mut stream, &mut inbuf, dur).await?;
        match ctype {
            REC_CHANGE_CIPHER_SPEC => continue, // middlebox compatibility
            REC_ALERT => return Err(alert_text(&payload)),
            REC_HANDSHAKE => {
                transcript.update(&payload);
                break parse_server_hello(&payload)?;
            }
            _ => return Err("unexpected record before ServerHello".into()),
        }
    };

    let shared = x25519(&secret, &server_pub);
    // An all-zero shared secret means a small-order point: the peer's key
    // contributes nothing and the "secret" is public. RFC 7748 §6.1 says to
    // abort.
    if shared.iter().all(|&b| b == 0) {
        return Err("server key share is a small-order point".into());
    }

    let schedule = KeySchedule::new(&shared, &transcript.clone().finish());
    let mut server_keys = Keys::from_secret(&schedule.server_hs, suite);
    let mut client_keys = Keys::from_secret(&schedule.client_hs, suite);

    // ── Server flight: EncryptedExtensions, Certificate, CertificateVerify,
    //    Finished — all inside encrypted records. ────────────────────────────
    let mut alpn_selected: Option<String> = None;
    let mut certificates: Vec<Vec<u8>> = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    // The loop yields the transcript hash as of just before the server's
    // Finished — what its verify_data is computed over — and the Finished
    // itself, so neither can be observed in a half-set state.
    let (verify_hash, server_finished) = 'flight: loop {
        let (ctype, payload) = next_record(&mut stream, &mut inbuf, dur).await?;
        match ctype {
            REC_CHANGE_CIPHER_SPEC => continue,
            REC_ALERT => return Err(alert_text(&payload)),
            REC_APPLICATION => {
                let mut header = Vec::with_capacity(5);
                header.push(REC_APPLICATION);
                header.extend_from_slice(&[0x03, 0x03]);
                header.extend_from_slice(&u16b(payload.len() as u16));
                let (inner_type, data) =
                    decrypt_record(suite, &mut server_keys, &header, &payload)?;
                match inner_type {
                    REC_ALERT => return Err(alert_text(&data)),
                    REC_HANDSHAKE => {
                        pending.extend_from_slice(&data);
                        // A record can hold several handshake messages, and a
                        // message can straddle two records.
                        while pending.len() >= 4 {
                            let mlen = ((pending[1] as usize) << 16)
                                | ((pending[2] as usize) << 8)
                                | pending[3] as usize;
                            if pending.len() < 4 + mlen {
                                break;
                            }
                            let msg: Vec<u8> = pending.drain(..4 + mlen).collect();
                            match msg[0] {
                                HS_ENCRYPTED_EXTENSIONS => {
                                    alpn_selected = parse_encrypted_extensions(&msg[4..]);
                                    transcript.update(&msg);
                                }
                                HS_CERTIFICATE => {
                                    certificates = parse_certificate_msg(&msg[4..]);
                                    transcript.update(&msg);
                                }
                                HS_CERTIFICATE_VERIFY => {
                                    transcript.update(&msg);
                                }
                                HS_FINISHED => {
                                    // The hash the server authenticated covers
                                    // everything *before* this message.
                                    let before = transcript.clone().finish();
                                    transcript.update(&msg);
                                    break 'flight (before, msg[4..].to_vec());
                                }
                                _ => transcript.update(&msg),
                            }
                        }
                    }
                    _ => return Err("unexpected content type in the server flight".into()),
                }
            }
            _ => return Err("unexpected plaintext record after ServerHello".into()),
        }
    };

    // ── Verify the server's Finished ───────────────────────────────────────
    let finished_key = hkdf_expand_label(&schedule.server_hs, "finished", b"", 32);
    let expected = hmac_sha256(&finished_key, &verify_hash);
    if !ct_eq(&expected, &server_finished) {
        return Err("server Finished did not verify — wrong keys or a tampered handshake".into());
    }

    // ── Certificate checks ─────────────────────────────────────────────────
    let (cert_summary, names_ok) = check_certificate(certificates.first().map(|v| v.as_slice()), host)?;

    // ── Client Finished, then the application keys ─────────────────────────
    let transcript_after_sf = transcript.clone().finish();
    let (client_ap, server_ap) = schedule.application(&transcript_after_sf);

    let cf_key = hkdf_expand_label(&schedule.client_hs, "finished", b"", 32);
    let cf_data = hmac_sha256(&cf_key, &transcript_after_sf);
    let mut cf = Vec::with_capacity(36);
    cf.push(HS_FINISHED);
    cf.extend_from_slice(&(32u32).to_be_bytes()[1..]);
    cf.extend_from_slice(&cf_data);

    // A bare ChangeCipherSpec first, purely so middleboxes see what they expect.
    let mut out = vec![REC_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    out.extend_from_slice(&encrypt_record(suite, &mut client_keys, REC_HANDSHAKE, &cf));
    timeout(dur, stream.write_all(&out))
        .await
        .map_err(|_| "TLS write timed out".to_string())?
        .map_err(|e| format!("TLS write failed: {e}"))?;

    Ok(TlsSession {
        stream,
        suite,
        client: Keys::from_secret(&client_ap, suite),
        server: Keys::from_secret(&server_ap, suite),
        inbuf,
        plain: Vec::new(),
        alpn: alpn_selected,
        cert_summary,
        cert_trusted_names: names_ok,
    })
}

fn parse_server_hello(msg: &[u8]) -> Result<(Suite, [u8; 32]), String> {
    if msg.len() < 4 || msg[0] != HS_SERVER_HELLO {
        return Err("expected a ServerHello".into());
    }
    let body = &msg[4..];
    if body.len() < 35 {
        return Err("short ServerHello".into());
    }
    if body[2..34] == HELLO_RETRY_RANDOM {
        return Err(
            "server asked for a HelloRetryRequest: it will not use X25519, which is the \
             only group this client offers"
                .into(),
        );
    }
    let sid_len = body[34] as usize;
    let mut i = 35 + sid_len;
    if body.len() < i + 3 {
        return Err("short ServerHello".into());
    }
    let suite_id = ((body[i] as u16) << 8) | body[i + 1] as u16;
    let suite = Suite::from_id(suite_id)
        .ok_or_else(|| format!("server chose cipher suite 0x{suite_id:04x}, which this client does not implement"))?;
    i += 3; // cipher suite + compression method

    if body.len() < i + 2 {
        return Err("ServerHello has no extensions".into());
    }
    let ext_len = ((body[i] as usize) << 8) | body[i + 1] as usize;
    i += 2;
    let end = (i + ext_len).min(body.len());

    let mut key_share: Option<[u8; 32]> = None;
    let mut version_ok = false;
    while i + 4 <= end {
        let id = ((body[i] as u16) << 8) | body[i + 1] as u16;
        let len = ((body[i + 2] as usize) << 8) | body[i + 3] as usize;
        i += 4;
        if i + len > end {
            break;
        }
        let val = &body[i..i + len];
        match id {
            43 => version_ok = val == [0x03, 0x04],
            51 if len >= 4 => {
                let group = ((val[0] as u16) << 8) | val[1] as u16;
                let klen = ((val[2] as usize) << 8) | val[3] as usize;
                if group == 0x001d && klen == 32 && val.len() >= 4 + 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&val[4..36]);
                    key_share = Some(k);
                }
            }
            _ => {}
        }
        i += len;
    }

    if !version_ok {
        return Err("server did not select TLS 1.3".into());
    }
    let key_share = key_share.ok_or("server sent no usable X25519 key share")?;
    Ok((suite, key_share))
}

fn parse_encrypted_extensions(body: &[u8]) -> Option<String> {
    if body.len() < 2 {
        return None;
    }
    let total = ((body[0] as usize) << 8) | body[1] as usize;
    let mut i = 2;
    let end = (2 + total).min(body.len());
    while i + 4 <= end {
        let id = ((body[i] as u16) << 8) | body[i + 1] as u16;
        let len = ((body[i + 2] as usize) << 8) | body[i + 3] as usize;
        i += 4;
        if i + len > end {
            break;
        }
        if id == 16 && len >= 3 {
            // ALPN: list length, then one length-prefixed protocol.
            let plen = body[i + 2] as usize;
            if i + 3 + plen <= end {
                return String::from_utf8(body[i + 3..i + 3 + plen].to_vec()).ok();
            }
        }
        i += len;
    }
    None
}

/// Split a TLS 1.3 Certificate message into its DER entries.
fn parse_certificate_msg(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if body.is_empty() {
        return out;
    }
    let ctx_len = body[0] as usize;
    let mut i = 1 + ctx_len;
    if i + 3 > body.len() {
        return out;
    }
    let list_len =
        ((body[i] as usize) << 16) | ((body[i + 1] as usize) << 8) | body[i + 2] as usize;
    i += 3;
    let end = (i + list_len).min(body.len());
    while i + 3 <= end {
        let clen =
            ((body[i] as usize) << 16) | ((body[i + 1] as usize) << 8) | body[i + 2] as usize;
        i += 3;
        if i + clen > end {
            break;
        }
        out.push(body[i..i + clen].to_vec());
        i += clen;
        // Skip this entry's extensions.
        if i + 2 > end {
            break;
        }
        let elen = ((body[i] as usize) << 8) | body[i + 1] as usize;
        i += 2 + elen;
    }
    out
}

/// Check the leaf certificate's names and dates, reusing the DER parsing that
/// `tls.rs` already does for `-sV`. Returns (summary, names_matched).
///
/// A name mismatch or an expired certificate is fatal: those are the checks
/// this client *can* make, so it makes them properly. The issuer chain is a
/// separate question it cannot answer — see the module docs.
fn check_certificate(cert: Option<&[u8]>, host: &str) -> Result<(String, bool), String> {
    let cert = match cert {
        Some(c) if !c.is_empty() => c,
        _ => return Err("server sent no certificate".into()),
    };

    let mut names = crate::tls::der_dns_sans(cert);
    if names.is_empty() {
        names = crate::tls::der_common_names(cert);
    }

    let (expiry, expired) =
        crate::tls::der_not_after(cert).unwrap_or_else(|| ("unknown".to_string(), false));
    if expired {
        return Err(format!(
            "server certificate expired on {expiry} — refusing to use this channel"
        ));
    }

    // An IP literal target has no name to match against; say so instead of
    // pretending the check passed.
    let checked = is_dns_name(host);
    let matched = !checked || names.iter().any(|n| hostname_matches(n, host));
    if checked && !matched {
        return Err(format!(
            "certificate is for {} — not for {host}",
            if names.is_empty() {
                "no listed name".to_string()
            } else {
                names.join(", ")
            }
        ));
    }

    let shown: Vec<String> = names.iter().take(3).cloned().collect();
    let summary = format!(
        "{} (expires {expiry})",
        if shown.is_empty() {
            "unnamed certificate".to_string()
        } else {
            shown.join(", ")
        }
    );
    Ok((summary, checked && matched))
}

impl TlsSession {
    /// Send application data.
    pub async fn write(&mut self, data: &[u8], timeout_ms: u64) -> Result<(), String> {
        let dur = Duration::from_millis(timeout_ms.max(2000));
        let rec = encrypt_record(self.suite, &mut self.client, REC_APPLICATION, data);
        timeout(dur, self.stream.write_all(&rec))
            .await
            .map_err(|_| "TLS write timed out".to_string())?
            .map_err(|e| format!("TLS write failed: {e}"))
    }

    /// Read at least `want` bytes of application data, or everything up to the
    /// peer's close_notify when `want` is 0.
    pub async fn read(&mut self, want: usize, timeout_ms: u64) -> Result<Vec<u8>, String> {
        let dur = Duration::from_millis(timeout_ms.max(2000));
        loop {
            if want > 0 && self.plain.len() >= want {
                return Ok(std::mem::take(&mut self.plain));
            }
            let (ctype, payload) = match next_record(&mut self.stream, &mut self.inbuf, dur).await {
                Ok(v) => v,
                Err(e) => {
                    // A clean end of stream with data already buffered is a
                    // complete answer, not a failure.
                    if !self.plain.is_empty() {
                        return Ok(std::mem::take(&mut self.plain));
                    }
                    return Err(e);
                }
            };
            match ctype {
                REC_CHANGE_CIPHER_SPEC => continue,
                REC_APPLICATION => {
                    let mut header = Vec::with_capacity(5);
                    header.push(REC_APPLICATION);
                    header.extend_from_slice(&[0x03, 0x03]);
                    header.extend_from_slice(&u16b(payload.len() as u16));
                    let (inner, data) =
                        decrypt_record(self.suite, &mut self.server, &header, &payload)?;
                    match inner {
                        REC_APPLICATION => self.plain.extend_from_slice(&data),
                        REC_ALERT => {
                            // close_notify after a complete answer is normal.
                            if data.len() >= 2 && data[1] == 0 {
                                return Ok(std::mem::take(&mut self.plain));
                            }
                            return Err(alert_text(&data));
                        }
                        // Post-handshake messages (session tickets, key update
                        // requests) are not needed for a single query.
                        REC_HANDSHAKE => continue,
                        _ => continue,
                    }
                }
                REC_ALERT => return Err(alert_text(&payload)),
                _ => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sha256_fips_vectors() {
        assert_eq!(
            sha256(b"abc").to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            sha256(b"").to_vec(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
            hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
        // Multi-block, exercising the streaming path across an update boundary.
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            h.finish().to_vec(),
            hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk.to_vec(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        assert_eq!(
            hkdf_expand(&prk, &info, 42),
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
    }

    #[test]
    fn x25519_rfc7748_vectors() {
        let mut scalar = [0u8; 32];
        let mut point = [0u8; 32];
        scalar.copy_from_slice(&hex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        ));
        point.copy_from_slice(&hex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        ));
        assert_eq!(
            x25519(&scalar, &point).to_vec(),
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );

        scalar.copy_from_slice(&hex(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        ));
        point.copy_from_slice(&hex(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        ));
        assert_eq!(
            x25519(&scalar, &point).to_vec(),
            hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        );
    }

    #[test]
    fn x25519_diffie_hellman_agrees() {
        // RFC 7748 s6.1: both sides must land on the same shared secret.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a.copy_from_slice(&hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        b.copy_from_slice(&hex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            x25519_base(&a).to_vec(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            x25519_base(&b).to_vec(),
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&a, &x25519_base(&b)).to_vec(), shared);
        assert_eq!(x25519(&b, &x25519_base(&a)).to_vec(), shared);
    }

    #[test]
    fn chacha20poly1305_rfc8439_vector() {
        // RFC 8439 s2.8.2
        let mut key = [0u8; 32];
        key.copy_from_slice(&hex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        ));
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hex("070000004041424344454647"));
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plain = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = chacha20poly1305_seal(&key, &nonce, &aad, plain);
        assert_eq!(
            sealed[..plain.len()].to_vec(),
            hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
        );
        assert_eq!(
            sealed[plain.len()..].to_vec(),
            hex("1ae10b594f09e26a7e902ecbd0600691")
        );
        assert_eq!(
            chacha20poly1305_open(&key, &nonce, &aad, &sealed).unwrap(),
            plain.to_vec()
        );
        // A flipped bit must not open.
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(chacha20poly1305_open(&key, &nonce, &aad, &bad).is_none());
    }

    #[test]
    fn hostname_matching_follows_the_wildcard_rule() {
        assert!(hostname_matches("example.com", "example.com"));
        assert!(hostname_matches("Example.COM", "example.com"));
        assert!(hostname_matches("example.com", "example.com."));
        assert!(hostname_matches("*.example.com", "a.example.com"));
        // A wildcard covers one label, never two.
        assert!(!hostname_matches("*.example.com", "a.b.example.com"));
        // ...and never the bare domain.
        assert!(!hostname_matches("*.example.com", "example.com"));
        assert!(!hostname_matches("example.com", "notexample.com"));
        assert!(!hostname_matches("example.com", "example.com.evil.test"));
    }

    #[test]
    fn sni_is_never_an_ip_literal() {
        assert!(is_dns_name("dns.google"));
        assert!(!is_dns_name("1.1.1.1"));
        assert!(!is_dns_name("::1"));
        assert!(!is_dns_name(""));
        assert!(!is_dns_name("localhost")); // no dot: not a public name
    }

    #[test]
    fn aes128_gcm_nist_vector() {
        // NIST GCM test case 4 (16-byte key, 12-byte IV, AAD present).
        let mut key = [0u8; 16];
        key.copy_from_slice(&hex("feffe9928665731c6d6a8f9467308308"));
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hex("cafebabefacedbaddecaf888"));
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plain = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let sealed = aes128gcm_seal(&key, &nonce, &aad, &plain);
        assert_eq!(
            sealed[..plain.len()].to_vec(),
            hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
        );
        assert_eq!(
            sealed[plain.len()..].to_vec(),
            hex("5bc94fbc3221a5db94fae95ae7121a47")
        );
        assert_eq!(
            aes128gcm_open(&key, &nonce, &aad, &sealed).unwrap(),
            plain
        );
        let mut bad = sealed.clone();
        bad[3] ^= 0x80;
        assert!(aes128gcm_open(&key, &nonce, &aad, &bad).is_none());
    }
}
