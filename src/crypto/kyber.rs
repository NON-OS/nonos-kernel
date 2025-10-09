use alloc::vec::Vec;
use crate::crypto::rng::random_u64;

const KYBER_Q: u16 = 3329;
const KYBER_N: usize = 256;
const KYBER_K: usize = 3;
const KYBER_ETA: u16 = 2;

#[repr(C)]
pub struct KyberPublicKey {
    pub a: [[u16; KYBER_N]; KYBER_K],
    pub t: [[u16; KYBER_N]; KYBER_K],
    pub rho: [u8; 32],
}

#[repr(C)]
pub struct KyberSecretKey {
    pub s: [[u16; KYBER_N]; KYBER_K],
}

#[repr(C)]
pub struct KyberCiphertext {
    pub u: [[u16; KYBER_N]; KYBER_K],
    pub v: [u16; KYBER_N],
}

#[repr(C)]
pub struct KyberKeyPair {
    pub public_key: KyberPublicKey,
    pub secret_key: KyberSecretKey,
}

fn mod_q(x: i32) -> u16 {
    let mut result = x % KYBER_Q as i32;
    if result < 0 {
        result += KYBER_Q as i32;
    }
    result as u16
}

fn barrett_reduce(x: u32) -> u16 {
    let v = ((1u64 << 26) + KYBER_Q as u64 / 2) / KYBER_Q as u64;
    let t = (v * x as u64 + (1u64 << 25)) >> 26;
    mod_q(x as i32 - (t * KYBER_Q as u64) as i32)
}

fn montgomery_reduce(a: u32) -> u16 {
    const QINV: u32 = 62209;
    const R: u32 = 1 << 16;
    
    let u = a.wrapping_mul(QINV) & 0xFFFF;
    let t = a.wrapping_add(u.wrapping_mul(KYBER_Q as u32)) >> 16;
    
    if t >= KYBER_Q as u32 {
        (t - KYBER_Q as u32) as u16
    } else {
        t as u16
    }
}

fn ntt_zetas() -> [u16; 128] {
    [
        2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
        2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
        732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
        1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
        107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
        430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
        1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
        418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
        1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
        478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
    ]
}

fn ntt(poly: &mut [u16; KYBER_N]) {
    let zetas = ntt_zetas();
    let mut len = 128;
    let mut k = 1;
    
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = zetas[k];
            k += 1;
            
            for j in start..start + len {
                let t = montgomery_reduce(zeta as u32 * poly[j + len] as u32);
                poly[j + len] = mod_q(poly[j] as i32 - t as i32);
                poly[j] = mod_q(poly[j] as i32 + t as i32);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

fn invntt(poly: &mut [u16; KYBER_N]) {
    let zetas = ntt_zetas();
    let mut len = 2;
    let mut k = 127;
    
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = zetas[k];
            k -= 1;
            
            for j in start..start + len {
                let t = poly[j];
                poly[j] = barrett_reduce(t as u32 + poly[j + len] as u32);
                poly[j + len] = montgomery_reduce(zeta as u32 * (poly[j + len] as i32 - t as i32 + KYBER_Q as i32) as u32);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    
    for i in 0..KYBER_N {
        poly[i] = montgomery_reduce(poly[i] as u32 * 1441);
    }
}

fn basemul(a: &[u16; KYBER_N], b: &[u16; KYBER_N], zeta: u16) -> [u16; KYBER_N] {
    let mut result = [0u16; KYBER_N];
    
    for i in (0..KYBER_N).step_by(2) {
        result[i] = montgomery_reduce(
            a[i] as u32 * b[i] as u32 + 
            montgomery_reduce(a[i + 1] as u32 * b[i + 1] as u32 * zeta as u32) as u32
        );
        result[i + 1] = montgomery_reduce(
            a[i] as u32 * b[i + 1] as u32 +
            a[i + 1] as u32 * b[i] as u32
        );
    }
    
    result
}

fn poly_add(a: &[u16; KYBER_N], b: &[u16; KYBER_N]) -> [u16; KYBER_N] {
    let mut result = [0u16; KYBER_N];
    for i in 0..KYBER_N {
        result[i] = mod_q(a[i] as i32 + b[i] as i32);
    }
    result
}

fn poly_sub(a: &[u16; KYBER_N], b: &[u16; KYBER_N]) -> [u16; KYBER_N] {
    let mut result = [0u16; KYBER_N];
    for i in 0..KYBER_N {
        result[i] = mod_q(a[i] as i32 - b[i] as i32);
    }
    result
}

fn poly_compress(poly: &[u16; KYBER_N], d: u8) -> Vec<u8> {
    let mut result = Vec::new();
    let mask = (1u16 << d) - 1;
    
    for &coeff in poly {
        let compressed = ((coeff as u32 * (1u32 << d) + KYBER_Q as u32 / 2) / KYBER_Q as u32) as u16 & mask;
        result.extend_from_slice(&compressed.to_le_bytes());
    }
    
    result
}

fn poly_decompress(data: &[u8], d: u8) -> [u16; KYBER_N] {
    let mut result = [0u16; KYBER_N];
    
    for (i, chunk) in data.chunks(2).enumerate() {
        if i >= KYBER_N { break; }
        let compressed = u16::from_le_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0)]);
        result[i] = ((compressed as u32 * KYBER_Q as u32 + (1u32 << (d - 1))) >> d) as u16;
    }
    
    result
}

fn sample_noise(eta: u16) -> [u16; KYBER_N] {
    let mut poly = [0u16; KYBER_N];
    
    for i in 0..KYBER_N {
        let mut a = 0i32;
        let mut b = 0i32;
        
        for _ in 0..eta {
            if random_u64() & 1 == 1 { a += 1; } else { b += 1; }
        }
        
        poly[i] = mod_q(a - b);
    }
    
    poly
}

fn gen_matrix(rho: &[u8; 32]) -> [[u16; KYBER_N]; KYBER_K] {
    let mut matrix = [[0u16; KYBER_N]; KYBER_K];
    
    for i in 0..KYBER_K {
        for j in 0..KYBER_N {
            let seed = crate::crypto::hash::sha256(&[rho.as_slice(), &[i as u8], &[j as u8]].concat());
            matrix[i][j] = (u16::from_le_bytes([seed[0], seed[1]]) % KYBER_Q) as u16;
        }
    }
    
    matrix
}

pub fn kyber_keygen() -> KyberKeyPair {
    let mut rho = [0u8; 32];
    for i in 0..32 {
        rho[i] = (random_u64() & 0xFF) as u8;
    }
    
    let a = gen_matrix(&rho);
    let mut s = [[0u16; KYBER_N]; KYBER_K];
    let mut e = [[0u16; KYBER_N]; KYBER_K];
    
    for i in 0..KYBER_K {
        s[i] = sample_noise(KYBER_ETA);
        e[i] = sample_noise(KYBER_ETA);
        
        ntt(&mut s[i]);
        ntt(&mut e[i]);
    }
    
    let mut t = [[0u16; KYBER_N]; KYBER_K];
    for i in 0..KYBER_K {
        let mut temp = [0u16; KYBER_N];
        for j in 0..KYBER_K {
            let mul_result = basemul(&a[i], &s[j], 17);
            temp = poly_add(&temp, &mul_result);
        }
        t[i] = poly_add(&temp, &e[i]);
        invntt(&mut t[i]);
    }
    
    KyberKeyPair {
        public_key: KyberPublicKey { a, t, rho },
        secret_key: KyberSecretKey { s },
    }
}

pub fn kyber_encaps(public_key: &KyberPublicKey) -> (KyberCiphertext, [u8; 32]) {
    let mut m = [0u8; 32];
    for i in 0..32 {
        m[i] = (random_u64() & 0xFF) as u8;
    }
    
    let mut r = [[0u16; KYBER_N]; KYBER_K];
    let mut e1 = [[0u16; KYBER_N]; KYBER_K];
    let mut e2 = [0u16; KYBER_N];
    
    for i in 0..KYBER_K {
        r[i] = sample_noise(KYBER_ETA);
        e1[i] = sample_noise(KYBER_ETA);
        ntt(&mut r[i]);
    }
    e2 = sample_noise(KYBER_ETA);
    
    let mut u = [[0u16; KYBER_N]; KYBER_K];
    for i in 0..KYBER_K {
        let mut temp = [0u16; KYBER_N];
        for j in 0..KYBER_K {
            let mul_result = basemul(&public_key.a[j], &r[j], 17);
            temp = poly_add(&temp, &mul_result);
        }
        invntt(&mut temp);
        u[i] = poly_add(&temp, &e1[i]);
    }
    
    let mut v = [0u16; KYBER_N];
    for i in 0..KYBER_K {
        let mut temp_r = r[i];
        invntt(&mut temp_r);
        let mul_result = basemul(&public_key.t[i], &temp_r, 17);
        v = poly_add(&v, &mul_result);
    }
    v = poly_add(&v, &e2);
    
    let msg_poly = bytes_to_poly(&m);
    v = poly_add(&v, &msg_poly);
    
    let shared_secret = crate::crypto::hash::sha256(&m);
    
    (KyberCiphertext { u, v }, shared_secret)
}

pub fn kyber_decaps(ciphertext: &KyberCiphertext, secret_key: &KyberSecretKey) -> [u8; 32] {
    let mut temp = [0u16; KYBER_N];
    
    for i in 0..KYBER_K {
        let mut temp_s = secret_key.s[i];
        invntt(&mut temp_s);
        let mul_result = basemul(&ciphertext.u[i], &temp_s, 17);
        temp = poly_add(&temp, &mul_result);
    }
    
    let msg_poly = poly_sub(&ciphertext.v, &temp);
    let recovered_msg = poly_to_bytes(&msg_poly);
    
    crate::crypto::hash::sha256(&recovered_msg)
}

fn bytes_to_poly(bytes: &[u8; 32]) -> [u16; KYBER_N] {
    let mut poly = [0u16; KYBER_N];
    
    for i in 0..32 {
        for j in 0..8 {
            if i * 8 + j < KYBER_N {
                poly[i * 8 + j] = ((bytes[i] >> j) & 1) as u16 * (KYBER_Q / 2);
            }
        }
    }
    
    poly
}

fn poly_to_bytes(poly: &[u16; KYBER_N]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    
    for i in 0..32 {
        for j in 0..8 {
            if i * 8 + j < KYBER_N {
                let bit = if poly[i * 8 + j] > KYBER_Q / 2 { 1 } else { 0 };
                bytes[i] |= bit << j;
            }
        }
    }
    
    bytes
}

pub fn kyber_serialize_public_key(pk: &KyberPublicKey) -> Vec<u8> {
    let mut result = Vec::new();
    
    for i in 0..KYBER_K {
        for j in 0..KYBER_N {
            result.extend_from_slice(&pk.a[i][j].to_le_bytes());
        }
    }
    
    for i in 0..KYBER_K {
        for j in 0..KYBER_N {
            result.extend_from_slice(&pk.t[i][j].to_le_bytes());
        }
    }
    
    result.extend_from_slice(&pk.rho);
    result
}

pub fn kyber_deserialize_public_key(data: &[u8]) -> Result<KyberPublicKey, &'static str> {
    if data.len() < (2 * KYBER_K * KYBER_N * 2 + 32) {
        return Err("Invalid public key data");
    }
    
    let mut pk = KyberPublicKey {
        a: [[0; KYBER_N]; KYBER_K],
        t: [[0; KYBER_N]; KYBER_K],
        rho: [0; 32],
    };
    
    let mut offset = 0;
    
    for i in 0..KYBER_K {
        for j in 0..KYBER_N {
            pk.a[i][j] = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
        }
    }
    
    for i in 0..KYBER_K {
        for j in 0..KYBER_N {
            pk.t[i][j] = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
        }
    }
    
    pk.rho.copy_from_slice(&data[offset..offset + 32]);
    
    Ok(pk)
}