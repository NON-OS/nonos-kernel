use crate::crypto::real_bls12_381::*;
use alloc::vec::Vec;

pub const KYBER_N: usize = 256;
pub const KYBER_Q: u32 = 3329;
pub const KYBER_K: usize = 2;
pub const KYBER_ETA1: u32 = 3;
pub const KYBER_ETA2: u32 = 2;
pub const KYBER_DU: usize = 10;
pub const KYBER_DV: usize = 4;

pub const DILITHIUM_N: usize = 256;
pub const DILITHIUM_Q: u32 = 8380417;
pub const DILITHIUM_D: usize = 13;
pub const DILITHIUM_TAU: usize = 39;
pub const DILITHIUM_BETA: u32 = 78;
pub const DILITHIUM_GAMMA1: u32 = 1048576;
pub const DILITHIUM_GAMMA2: u32 = 95232;

#[derive(Debug, Clone)]
pub struct PolynomialRing {
    pub coeffs: Vec<u32>,
    pub n: usize,
    pub q: u32,
}

#[derive(Debug, Clone)]
pub struct PolynomialVector {
    pub polys: Vec<PolynomialRing>,
    pub k: usize,
}

#[derive(Debug, Clone)]
pub struct PolynomialMatrix {
    pub rows: Vec<PolynomialVector>,
    pub k: usize,
    pub l: usize,
}

#[derive(Debug, Clone)]
pub struct KyberPublicKey {
    pub rho: [u8; 32],
    pub t: PolynomialVector,
}

#[derive(Debug, Clone)]
pub struct KyberSecretKey {
    pub s: PolynomialVector,
}

#[derive(Debug, Clone)]
pub struct KyberCiphertext {
    pub u: PolynomialVector,
    pub v: PolynomialRing,
}

#[derive(Debug, Clone)]
pub struct DilithiumPublicKey {
    pub rho: [u8; 32],
    pub t1: PolynomialVector,
}

#[derive(Debug, Clone)]
pub struct DilithiumSecretKey {
    pub rho: [u8; 32],
    pub tr: [u8; 32],
    pub s1: PolynomialVector,
    pub s2: PolynomialVector,
    pub t0: PolynomialVector,
}

#[derive(Debug, Clone)]
pub struct DilithiumSignature {
    pub z: PolynomialVector,
    pub h: PolynomialRing,
    pub c: [u8; 32],
}

impl PolynomialRing {
    pub fn new(n: usize, q: u32) -> Self {
        Self {
            coeffs: vec![0; n],
            n,
            q,
        }
    }
    
    pub fn from_coeffs(coeffs: Vec<u32>, q: u32) -> Self {
        let n = coeffs.len();
        Self { coeffs, n, q }
    }
    
    pub fn reduce(&mut self) {
        for coeff in &mut self.coeffs {
            *coeff = barrett_reduce(*coeff, self.q);
        }
    }
    
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new(self.n, self.q);
        for i in 0..self.n {
            result.coeffs[i] = barrett_reduce(self.coeffs[i] + other.coeffs[i], self.q);
        }
        result
    }
    
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new(self.n, self.q);
        for i in 0..self.n {
            result.coeffs[i] = barrett_reduce(self.coeffs[i] + self.q - other.coeffs[i], self.q);
        }
        result
    }
    
    pub fn mul(&self, other: &Self) -> Self {
        let mut a_ntt = self.clone();
        let mut b_ntt = other.clone();
        ntt_forward(&mut a_ntt.coeffs, self.q);
        ntt_forward(&mut b_ntt.coeffs, self.q);
        
        let mut result = Self::new(self.n, self.q);
        for i in 0..self.n {
            result.coeffs[i] = montgomery_reduce(
                (a_ntt.coeffs[i] as u64) * (b_ntt.coeffs[i] as u64),
                self.q
            );
        }
        
        ntt_inverse(&mut result.coeffs, self.q);
        result
    }
    
    pub fn ntt(&mut self) {
        ntt_forward(&mut self.coeffs, self.q);
    }
    
    pub fn intt(&mut self) {
        ntt_inverse(&mut self.coeffs, self.q);
    }
    
    pub fn pointwise_mul(&self, other: &Self) -> Self {
        let mut result = Self::new(self.n, self.q);
        for i in 0..self.n {
            result.coeffs[i] = montgomery_reduce(
                (self.coeffs[i] as u64) * (other.coeffs[i] as u64),
                self.q
            );
        }
        result
    }
    
    pub fn from_bytes(bytes: &[u8], q: u32) -> Self {
        let n = KYBER_N;
        let mut poly = Self::new(n, q);
        
        if q == KYBER_Q {
            for i in 0..n / 2 {
                let t0 = bytes[3 * i] as u32;
                let t1 = bytes[3 * i + 1] as u32;
                let t2 = bytes[3 * i + 2] as u32;
                
                poly.coeffs[2 * i] = t0 | ((t1 & 0x0F) << 8);
                poly.coeffs[2 * i + 1] = (t1 >> 4) | (t2 << 4);
            }
        } else if q == DILITHIUM_Q {
            for i in 0..n {
                let idx = i * 3;
                if idx + 2 < bytes.len() {
                    poly.coeffs[i] = (bytes[idx] as u32) |
                                   ((bytes[idx + 1] as u32) << 8) |
                                   ((bytes[idx + 2] as u32) << 16);
                }
            }
        }
        
        poly
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        if self.q == KYBER_Q {
            for i in 0..self.n / 2 {
                let t0 = self.coeffs[2 * i] & 0xFFF;
                let t1 = self.coeffs[2 * i + 1] & 0xFFF;
                
                bytes.push(t0 as u8);
                bytes.push(((t0 >> 8) | (t1 << 4)) as u8);
                bytes.push((t1 >> 4) as u8);
            }
        } else if self.q == DILITHIUM_Q {
            for &coeff in &self.coeffs {
                bytes.push(coeff as u8);
                bytes.push((coeff >> 8) as u8);
                bytes.push((coeff >> 16) as u8);
            }
        }
        
        bytes
    }
    
    pub fn sample_binomial(n: usize, q: u32, eta: u32, seed: &[u8]) -> Self {
        let mut poly = Self::new(n, q);
        let mut rng_state = sha3_256(seed);
        
        for i in 0..n {
            let mut sum = 0i32;
            
            for _ in 0..eta {
                rng_state = xof_squeeze(&rng_state);
                let a = (rng_state[0] & 1) as i32;
                let b = ((rng_state[0] >> 1) & 1) as i32;
                sum += a - b;
            }
            
            poly.coeffs[i] = if sum >= 0 {
                sum as u32
            } else {
                (q as i32 + sum) as u32
            };
        }
        
        poly
    }
    
    pub fn uniform_from_seed(seed: &[u8], nonce: u16, q: u32) -> Self {
        let n = if q == KYBER_Q { KYBER_N } else { DILITHIUM_N };
        let mut poly = Self::new(n, q);
        
        let mut expanded_seed = Vec::from(seed);
        expanded_seed.extend_from_slice(&nonce.to_le_bytes());
        
        let mut stream = shake256(&expanded_seed, n * 3);
        let mut idx = 0;
        let mut pos = 0;
        
        while idx < n && pos + 2 < stream.len() {
            let val = ((stream[pos] as u32) |
                      ((stream[pos + 1] as u32) << 8)) & 0x1FFF;
            
            if val < q {
                poly.coeffs[idx] = val;
                idx += 1;
            }
            pos += 2;
        }
        
        poly
    }
    
    pub fn compress(&self, d: usize) -> Vec<u8> {
        let mut compressed = Vec::new();
        let t = 1u32 << d;
        
        for i in 0..self.n {
            let x = ((self.coeffs[i] as u64 * t as u64 + self.q as u64 / 2) / self.q as u64) as u32;
            let compressed_val = x & (t - 1);
            
            if d == 1 {
                if i % 8 == 0 {
                    compressed.push(0);
                }
                let byte_idx = compressed.len() - 1;
                compressed[byte_idx] |= (compressed_val as u8) << (i % 8);
            } else if d <= 8 {
                compressed.push(compressed_val as u8);
            } else {
                compressed.extend_from_slice(&compressed_val.to_le_bytes()[..((d + 7) / 8)]);
            }
        }
        
        compressed
    }
    
    pub fn decompress(data: &[u8], n: usize, q: u32, d: usize) -> Self {
        let mut poly = Self::new(n, q);
        let t = 1u32 << d;
        
        for i in 0..n {
            let compressed_val = if d == 1 {
                ((data[i / 8] >> (i % 8)) & 1) as u32
            } else if d <= 8 {
                data[i] as u32
            } else {
                let byte_start = i * ((d + 7) / 8);
                let mut val = 0u32;
                for j in 0..((d + 7) / 8) {
                    if byte_start + j < data.len() {
                        val |= (data[byte_start + j] as u32) << (8 * j);
                    }
                }
                val & (t - 1)
            };
            
            poly.coeffs[i] = ((compressed_val as u64 * q as u64 + t as u64 / 2) / t as u64) as u32;
        }
        
        poly
    }
    
    pub fn power2round(&self, d: usize) -> (Self, Self) {
        let mut r1 = Self::new(self.n, self.q);
        let mut r0 = Self::new(self.n, self.q);
        let t = 1u32 << d;
        
        for i in 0..self.n {
            let r0_val = self.coeffs[i] & (t - 1);
            r0.coeffs[i] = if r0_val > t / 2 { r0_val - t } else { r0_val };
            r1.coeffs[i] = (self.coeffs[i] - r0_val) / t;
        }
        
        (r1, r0)
    }
    
    pub fn decompose(&self, alpha: u32) -> (Self, Self) {
        let mut r1 = Self::new(self.n, self.q);
        let mut r0 = Self::new(self.n, self.q);
        
        for i in 0..self.n {
            let a = self.coeffs[i];
            let a1 = (a + 127) >> 7;
            let a1 = if a1 * 1025 + (1 << 21) < self.q { a1 } else { a1 - 1 };
            let a0 = a - a1 * alpha;
            
            r1.coeffs[i] = a1;
            r0.coeffs[i] = if a0 > alpha / 2 { a0 - alpha } else { a0 };
        }
        
        (r1, r0)
    }
    
    pub fn make_hint(&self, other: &Self, alpha: u32) -> Self {
        let mut hint = Self::new(self.n, self.q);
        
        for i in 0..self.n {
            let (r1, _) = self.decompose(alpha);
            let (s1, _) = other.decompose(alpha);
            hint.coeffs[i] = if r1.coeffs[i] != s1.coeffs[i] { 1 } else { 0 };
        }
        
        hint
    }
    
    pub fn use_hint(&self, hint: &Self, alpha: u32) -> Self {
        let mut result = Self::new(self.n, self.q);
        
        for i in 0..self.n {
            let (mut r1, r0) = self.decompose(alpha);
            
            if hint.coeffs[i] == 1 {
                if r0.coeffs[i] > 0 {
                    r1.coeffs[i] = (r1.coeffs[i] + 1) % ((self.q - 1) / alpha);
                } else {
                    r1.coeffs[i] = if r1.coeffs[i] == 0 {
                        (self.q - 1) / alpha - 1
                    } else {
                        r1.coeffs[i] - 1
                    };
                }
            }
            
            result.coeffs[i] = r1.coeffs[i];
        }
        
        result
    }
}

impl PolynomialVector {
    pub fn new(k: usize, n: usize, q: u32) -> Self {
        let mut polys = Vec::with_capacity(k);
        for _ in 0..k {
            polys.push(PolynomialRing::new(n, q));
        }
        Self { polys, k }
    }
    
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new(self.k, self.polys[0].n, self.polys[0].q);
        for i in 0..self.k {
            result.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        result
    }
    
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new(self.k, self.polys[0].n, self.polys[0].q);
        for i in 0..self.k {
            result.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        result
    }
    
    pub fn dot(&self, other: &Self) -> PolynomialRing {
        let mut result = PolynomialRing::new(self.polys[0].n, self.polys[0].q);
        for i in 0..self.k {
            let product = self.polys[i].mul(&other.polys[i]);
            result = result.add(&product);
        }
        result
    }
    
    pub fn ntt(&mut self) {
        for poly in &mut self.polys {
            poly.ntt();
        }
    }
    
    pub fn intt(&mut self) {
        for poly in &mut self.polys {
            poly.intt();
        }
    }
    
    pub fn pointwise_mul(&self, other: &Self) -> Self {
        let mut result = Self::new(self.k, self.polys[0].n, self.polys[0].q);
        for i in 0..self.k {
            result.polys[i] = self.polys[i].pointwise_mul(&other.polys[i]);
        }
        result
    }
    
    pub fn sample_binomial(k: usize, n: usize, q: u32, eta: u32, seed: &[u8]) -> Self {
        let mut polys = Vec::with_capacity(k);
        for i in 0..k {
            let mut poly_seed = Vec::from(seed);
            poly_seed.push(i as u8);
            polys.push(PolynomialRing::sample_binomial(n, q, eta, &poly_seed));
        }
        Self { polys, k }
    }
    
    pub fn uniform_from_seed(k: usize, seed: &[u8], nonce: u16, n: usize, q: u32) -> Self {
        let mut polys = Vec::with_capacity(k);
        for i in 0..k {
            polys.push(PolynomialRing::uniform_from_seed(seed, nonce + i as u16, q));
        }
        Self { polys, k }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for poly in &self.polys {
            bytes.extend(poly.to_bytes());
        }
        bytes
    }
    
    pub fn from_bytes(bytes: &[u8], k: usize, n: usize, q: u32) -> Self {
        let poly_bytes = if q == KYBER_Q {
            (n * 12) / 8
        } else {
            n * 3
        };
        
        let mut polys = Vec::with_capacity(k);
        for i in 0..k {
            let start = i * poly_bytes;
            let end = start + poly_bytes;
            if end <= bytes.len() {
                polys.push(PolynomialRing::from_bytes(&bytes[start..end], q));
            } else {
                polys.push(PolynomialRing::new(n, q));
            }
        }
        
        Self { polys, k }
    }
    
    pub fn compress(&self, d: usize) -> Vec<u8> {
        let mut compressed = Vec::new();
        for poly in &self.polys {
            compressed.extend(poly.compress(d));
        }
        compressed
    }
    
    pub fn decompress(data: &[u8], k: usize, n: usize, q: u32, d: usize) -> Self {
        let bytes_per_poly = n * d / 8;
        let mut polys = Vec::with_capacity(k);
        
        for i in 0..k {
            let start = i * bytes_per_poly;
            let end = start + bytes_per_poly;
            if end <= data.len() {
                polys.push(PolynomialRing::decompress(&data[start..end], n, q, d));
            } else {
                polys.push(PolynomialRing::new(n, q));
            }
        }
        
        Self { polys, k }
    }
    
    pub fn power2round(&self, d: usize) -> (Self, Self) {
        let mut high = Self::new(self.k, self.polys[0].n, self.polys[0].q);
        let mut low = Self::new(self.k, self.polys[0].n, self.polys[0].q);
        
        for i in 0..self.k {
            let (h, l) = self.polys[i].power2round(d);
            high.polys[i] = h;
            low.polys[i] = l;
        }
        
        (high, low)
    }
    
    pub fn infinity_norm(&self) -> u32 {
        let mut max_norm = 0u32;
        for poly in &self.polys {
            for &coeff in &poly.coeffs {
                let norm = if coeff > poly.q / 2 {
                    poly.q - coeff
                } else {
                    coeff
                };
                max_norm = max_norm.max(norm);
            }
        }
        max_norm
    }
}

impl PolynomialMatrix {
    pub fn new(k: usize, l: usize, n: usize, q: u32) -> Self {
        let mut rows = Vec::with_capacity(k);
        for _ in 0..k {
            rows.push(PolynomialVector::new(l, n, q));
        }
        Self { rows, k, l }
    }
    
    pub fn mul_vector(&self, vec: &PolynomialVector) -> PolynomialVector {
        let mut result = PolynomialVector::new(self.k, self.rows[0].polys[0].n, self.rows[0].polys[0].q);
        for i in 0..self.k {
            result.polys[i] = self.rows[i].dot(vec);
        }
        result
    }
    
    pub fn transpose(&self) -> Self {
        let mut transposed = Self::new(self.l, self.k, self.rows[0].polys[0].n, self.rows[0].polys[0].q);
        for i in 0..self.l {
            for j in 0..self.k {
                transposed.rows[i].polys[j] = self.rows[j].polys[i].clone();
            }
        }
        transposed
    }
    
    pub fn uniform_from_seed(k: usize, l: usize, seed: &[u8], n: usize, q: u32) -> Self {
        let mut rows = Vec::with_capacity(k);
        for i in 0..k {
            rows.push(PolynomialVector::uniform_from_seed(l, seed, i as u16, n, q));
        }
        Self { rows, k, l }
    }
    
    pub fn ntt(&mut self) {
        for row in &mut self.rows {
            row.ntt();
        }
    }
    
    pub fn intt(&mut self) {
        for row in &mut self.rows {
            row.intt();
        }
    }
}

fn barrett_reduce(a: u32, q: u32) -> u32 {
    let v = ((1u64 << 26) + q as u64 / 2) / q as u64;
    let t = (v * a as u64) >> 26;
    a - (t * q as u64) as u32
}

fn montgomery_reduce(a: u64, q: u32) -> u32 {
    let qinv = 62209; // -q^(-1) mod 2^16 for Kyber
    let m = (a * qinv as u64) & 0xFFFF;
    let t = (a + m * q as u64) >> 16;
    if t >= q as u64 { (t - q as u64) as u32 } else { t as u32 }
}

fn ntt_forward(poly: &mut [u32], q: u32) {
    let n = poly.len();
    let zetas = if q == KYBER_Q {
        get_kyber_zetas()
    } else {
        get_dilithium_zetas()
    };
    
    let mut k = 1;
    let mut len = 128;
    
    while len >= 2 {
        let mut start = 0;
        while start < n {
            let zeta = zetas[k];
            k += 1;
            
            for j in start..start + len {
                let t = montgomery_reduce(zeta as u64 * poly[j + len] as u64, q);
                poly[j + len] = barrett_reduce(poly[j] + q - t, q);
                poly[j] = barrett_reduce(poly[j] + t, q);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

fn ntt_inverse(poly: &mut [u32], q: u32) {
    let n = poly.len();
    let zetas = if q == KYBER_Q {
        get_kyber_zetas_inv()
    } else {
        get_dilithium_zetas_inv()
    };
    
    let mut k = 0;
    let mut len = 2;
    
    while len <= 128 {
        let mut start = 0;
        while start < n {
            let zeta = zetas[k];
            k += 1;
            
            for j in start..start + len {
                let t = poly[j];
                poly[j] = barrett_reduce(t + poly[j + len], q);
                poly[j + len] = montgomery_reduce(
                    zeta as u64 * (t + q - poly[j + len]) as u64,
                    q
                );
            }
            start += 2 * len;
        }
        len *= 2;
    }
    
    let ninv = if q == KYBER_Q { 3303 } else { 8347681 };
    for coeff in poly {
        *coeff = montgomery_reduce(ninv as u64 * *coeff as u64, q);
    }
}

fn get_kyber_zetas() -> [u32; 128] {
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

fn get_kyber_zetas_inv() -> [u32; 128] {
    [
        1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
        1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
        1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
        1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
        3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
        1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
        1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
        2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
        829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
        3127, 3042, 1907, 1836, 1517, 359, 758, 1441
    ]
}

fn get_dilithium_zetas() -> [u32; 256] {
    [
        0, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468,
        1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
        2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
        6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
        2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
        4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
        6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
        811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892, 5582638,
        4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
        7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
        3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
        7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
        5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
        4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561,
        189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
        1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
        2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
        266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
        900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917,
        7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
        342297, 286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044,
        2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
        4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
        7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
        7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031,
        7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136, 4603424,
        6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531, 7173032,
        5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310,
        5341501, 3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078,
        7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
        5441381, 6144432, 7959518, 6094090, 183443, 7403526, 1612842, 4834730,
        7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782
    ]
}

fn get_dilithium_zetas_inv() -> [u32; 256] {
    [
        6403635, 846154, 6979993, 4442679, 1362209, 48306, 4460757, 554416,
        3545687, 6767575, 976891, 8196974, 2286327, 420899, 2235985, 2939036,
        3833893, 260646, 1104333, 1667432, 6470041, 1803090, 6656817, 426683,
        7908339, 6662682, 975884, 6167306, 8110657, 4513516, 4856520, 3038916,
        1799107, 3694233, 6727783, 7570268, 5366416, 6764025, 8217573, 3183426,
        1207385, 8194886, 5011305, 6423145, 164721, 5925962, 5948022, 2013608,
        3776993, 7786281, 3724270, 2584293, 1846953, 1671176, 2831860, 542412,
        4974386, 6144537, 7603226, 6880252, 1374803, 2546312, 6463336, 1279661,
        1962642, 5074302, 7067962, 451100, 1430225, 3318210, 7143142, 1333058,
        1050970, 6476982, 6511298, 2994039, 3548272, 5744496, 7129092, 6128019,
        2702524, 7686619, 5674049, 8177228, 6475974, 4824158, 2542305, 2055342,
        5153459, 5800875, 5965283, 7089458, 6975688, 7833921, 4869530, 8237455,
        3251451, 5013555, 4193832, 7295980, 7561383, 2897722, 3940593, 8118445,
        8017364, 2525322, 2119393, 2074956, 886322, 624178, 6107014, 4002526,
        2857831, 4069509, 6325481, 4519373, 5132748, 2681338, 1235728, 5972392,
        1283388, 7836947, 3747792, 471247, 2542896, 3792043, 8265881, 3949217,
        6765618, 1097808, 8017330, 2699530, 2699439, 5066110, 8142030, 7414112,
        5436341, 5999181, 2521448, 2956955, 8357748, 3210685, 2795015, 1502238,
        4623773, 6829603, 6647005, 4720936, 1016939, 552450, 5426923, 5002266,
        5493076, 6515434, 2602618, 2797549, 6945567, 8333366, 8329091, 3904520,
        1667446, 5363326, 3966834, 4982821, 3919660, 852841, 6370288, 5210595,
        2380465, 6845784, 7530259, 4880672, 7029828, 4793933, 7604811, 5918583,
        2834896, 5543223, 5407395, 8268149, 2942492, 1235728, 856, 6273136,
        5251012, 1027856, 2080005, 1928421, 2842341, 2691481, 5790267, 1265009,
        4055324, 1247620, 2486353, 1595974, 4613401, 1250494, 2635921, 4832145,
        5386378, 1869119, 1903435, 7329447, 7047359, 1237275, 5062207, 6950192,
        7929317, 1312455, 3306115, 6417775, 7100756, 1917081, 5834105, 7005614,
        1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241, 6533464,
        5796124, 4656147, 594136, 4603424, 6366809, 2432395, 2454455, 8215696,
        1957272, 3369112, 185531, 7173032, 5196991, 162844, 1616392, 3014001,
        810149, 1652634, 4686184, 6581310, 5341501, 3523897, 3866901, 269760,
        2213111, 7404533, 1717735, 472078, 7953734, 1723600, 6577327, 1910376
    ]
}

fn sha3_256(data: &[u8]) -> [u8; 32] {
    crate::crypto::hash::blake3_hash(data)
}

fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut output = vec![0u8; output_len];
    let mut hash_input = data.to_vec();
    
    for i in 0..output_len / 32 {
        hash_input.push(i as u8);
        let hash = crate::crypto::hash::blake3_hash(&hash_input);
        let end = ((i + 1) * 32).min(output_len);
        output[i * 32..end].copy_from_slice(&hash[..end - i * 32]);
        hash_input.pop();
    }
    
    output
}

fn xof_squeeze(state: &[u8; 32]) -> [u8; 32] {
    let mut new_state = *state;
    new_state[0] = new_state[0].wrapping_add(1);
    crate::crypto::hash::blake3_hash(&new_state)
}

pub fn kyber_keygen() -> (KyberPublicKey, KyberSecretKey) {
    let mut rng_seed = [0u8; 32];
    for i in 0..32 {
        rng_seed[i] = (i as u64 * 0x123456789abcdef) as u8;
    }
    
    let rho = sha3_256(&rng_seed);
    let sigma = sha3_256(&[&rho[..], &[0x00]].concat());
    
    let a = PolynomialMatrix::uniform_from_seed(KYBER_K, KYBER_K, &rho, KYBER_N, KYBER_Q);
    let s = PolynomialVector::sample_binomial(KYBER_K, KYBER_N, KYBER_Q, KYBER_ETA1, &sigma);
    let e = PolynomialVector::sample_binomial(KYBER_K, KYBER_N, KYBER_Q, KYBER_ETA1, &[&sigma[..], &[0x01]].concat());
    
    let mut s_ntt = s.clone();
    s_ntt.ntt();
    
    let mut a_clone = a.clone();
    a_clone.ntt();
    
    let mut t = a_clone.mul_vector(&s_ntt);
    t.intt();
    let t = t.add(&e);
    
    (KyberPublicKey { rho, t }, KyberSecretKey { s })
}

pub fn kyber_encrypt(pk: &KyberPublicKey, msg: &[u8], coins: &[u8]) -> KyberCiphertext {
    let a = PolynomialMatrix::uniform_from_seed(KYBER_K, KYBER_K, &pk.rho, KYBER_N, KYBER_Q);
    let r = PolynomialVector::sample_binomial(KYBER_K, KYBER_N, KYBER_Q, KYBER_ETA1, coins);
    let e1 = PolynomialVector::sample_binomial(KYBER_K, KYBER_N, KYBER_Q, KYBER_ETA2, &[coins, &[0x00]].concat());
    let e2 = PolynomialRing::sample_binomial(KYBER_N, KYBER_Q, KYBER_ETA2, &[coins, &[0x01]].concat());
    
    let m = encode_message(msg, KYBER_N, KYBER_Q);
    
    let mut r_ntt = r.clone();
    r_ntt.ntt();
    
    let mut a_t = a.transpose();
    a_t.ntt();
    
    let mut u = a_t.mul_vector(&r_ntt);
    u.intt();
    let u = u.add(&e1);
    
    let mut t_ntt = pk.t.clone();
    t_ntt.ntt();
    
    let mut v = t_ntt.dot(&r_ntt);
    v.intt();
    let v = v.add(&e2).add(&m);
    
    KyberCiphertext { u, v }
}

pub fn kyber_decrypt(sk: &KyberSecretKey, ct: &KyberCiphertext) -> Vec<u8> {
    let mut s_ntt = sk.s.clone();
    s_ntt.ntt();
    
    let mut u_ntt = ct.u.clone();
    u_ntt.ntt();
    
    let mut m_recovery = s_ntt.dot(&u_ntt);
    m_recovery.intt();
    
    let m = ct.v.sub(&m_recovery);
    decode_message(&m)
}

pub fn dilithium_keygen() -> (DilithiumPublicKey, DilithiumSecretKey) {
    let mut rng_seed = [0u8; 32];
    for i in 0..32 {
        rng_seed[i] = (i as u64 * 0xfeedface12345678) as u8;
    }
    
    let rho = sha3_256(&rng_seed);
    let rho_prime = sha3_256(&[&rho[..], &[0x00]].concat());
    let key = sha3_256(&[&rho_prime[..], &[0x00]].concat());
    
    let a = PolynomialMatrix::uniform_from_seed(DILITHIUM_K, DILITHIUM_L, &rho, DILITHIUM_N, DILITHIUM_Q);
    let s1 = PolynomialVector::sample_binomial(DILITHIUM_L, DILITHIUM_N, DILITHIUM_Q, DILITHIUM_ETA, &rho_prime);
    let s2 = PolynomialVector::sample_binomial(DILITHIUM_K, DILITHIUM_N, DILITHIUM_Q, DILITHIUM_ETA, &[&rho_prime[..], &[0x01]].concat());
    
    let mut s1_ntt = s1.clone();
    s1_ntt.ntt();
    
    let mut a_clone = a.clone();
    a_clone.ntt();
    
    let mut t = a_clone.mul_vector(&s1_ntt);
    t.intt();
    let t = t.add(&s2);
    
    let (t1, t0) = t.power2round(DILITHIUM_D);
    
    let tr = sha3_256(&[&rho[..], &t1.to_bytes()].concat());
    
    (
        DilithiumPublicKey { rho, t1 },
        DilithiumSecretKey { rho, tr, s1, s2, t0 }
    )
}

pub fn dilithium_sign(sk: &DilithiumSecretKey, msg: &[u8]) -> DilithiumSignature {
    let a = PolynomialMatrix::uniform_from_seed(DILITHIUM_K, DILITHIUM_L, &sk.rho, DILITHIUM_N, DILITHIUM_Q);
    let mu = sha3_256(&[&sk.tr[..], msg].concat());
    
    let mut kappa = 0u16;
    
    loop {
        let y = PolynomialVector::sample_binomial(
            DILITHIUM_L,
            DILITHIUM_N,
            DILITHIUM_Q,
            DILITHIUM_GAMMA1,
            &[&sk.rho[..], &kappa.to_le_bytes()].concat()
        );
        
        let mut y_ntt = y.clone();
        y_ntt.ntt();
        
        let mut a_clone = a.clone();
        a_clone.ntt();
        
        let mut w = a_clone.mul_vector(&y_ntt);
        w.intt();
        
        let (w1, _) = w.decompose(2 * DILITHIUM_GAMMA2);
        
        let c_tilde = sha3_256(&[&mu[..], &w1.to_bytes()].concat());
        let c = sample_in_ball(&c_tilde, DILITHIUM_TAU);
        
        let mut c_ntt = c.clone();
        c_ntt.ntt();
        
        let mut s1_ntt = sk.s1.clone();
        s1_ntt.ntt();
        
        let mut cs1 = PolynomialVector::new(DILITHIUM_L, DILITHIUM_N, DILITHIUM_Q);
        for i in 0..DILITHIUM_L {
            cs1.polys[i] = c_ntt.pointwise_mul(&s1_ntt.polys[i]);
        }
        cs1.intt();
        
        let z = y.add(&cs1);
        
        if z.infinity_norm() >= DILITHIUM_GAMMA1 - DILITHIUM_BETA {
            kappa += 1;
            continue;
        }
        
        let mut s2_ntt = sk.s2.clone();
        s2_ntt.ntt();
        
        let mut cs2 = PolynomialVector::new(DILITHIUM_K, DILITHIUM_N, DILITHIUM_Q);
        for i in 0..DILITHIUM_K {
            cs2.polys[i] = c_ntt.pointwise_mul(&s2_ntt.polys[i]);
        }
        cs2.intt();
        
        let r0 = w.sub(&cs2);
        
        if r0.infinity_norm() >= DILITHIUM_GAMMA2 - DILITHIUM_BETA {
            kappa += 1;
            continue;
        }
        
        let mut ct0 = PolynomialVector::new(DILITHIUM_K, DILITHIUM_N, DILITHIUM_Q);
        for i in 0..DILITHIUM_K {
            ct0.polys[i] = c_ntt.pointwise_mul(&sk.t0.polys[i]);
        }
        ct0.intt();
        
        if ct0.infinity_norm() >= DILITHIUM_GAMMA2 {
            kappa += 1;
            continue;
        }
        
        let w_minus_cs2_plus_ct0 = w.sub(&cs2).add(&ct0);
        let (w1_check, w0) = w_minus_cs2_plus_ct0.decompose(2 * DILITHIUM_GAMMA2);
        
        if !vectors_equal(&w1, &w1_check) || w0.infinity_norm() >= DILITHIUM_GAMMA2 {
            kappa += 1;
            continue;
        }
        
        let h = make_hint(&w0, &w1, 2 * DILITHIUM_GAMMA2);
        
        return DilithiumSignature {
            z,
            h,
            c: c_tilde,
        };
    }
}

pub fn dilithium_verify(pk: &DilithiumPublicKey, msg: &[u8], sig: &DilithiumSignature) -> bool {
    if sig.z.infinity_norm() >= DILITHIUM_GAMMA1 - DILITHIUM_BETA {
        return false;
    }
    
    let c = sample_in_ball(&sig.c, DILITHIUM_TAU);
    let tr = sha3_256(&[&pk.rho[..], &pk.t1.to_bytes()].concat());
    let mu = sha3_256(&[&tr[..], msg].concat());
    
    let a = PolynomialMatrix::uniform_from_seed(DILITHIUM_K, DILITHIUM_L, &pk.rho, DILITHIUM_N, DILITHIUM_Q);
    
    let mut z_ntt = sig.z.clone();
    z_ntt.ntt();
    
    let mut a_clone = a.clone();
    a_clone.ntt();
    
    let mut az = a_clone.mul_vector(&z_ntt);
    az.intt();
    
    let mut c_ntt = c.clone();
    c_ntt.ntt();
    
    let mut t1_2d = pk.t1.clone();
    for poly in &mut t1_2d.polys {
        for coeff in &mut poly.coeffs {
            *coeff <<= DILITHIUM_D;
        }
    }
    
    let mut t1_2d_ntt = t1_2d.clone();
    t1_2d_ntt.ntt();
    
    let mut ct1 = PolynomialVector::new(DILITHIUM_K, DILITHIUM_N, DILITHIUM_Q);
    for i in 0..DILITHIUM_K {
        ct1.polys[i] = c_ntt.pointwise_mul(&t1_2d_ntt.polys[i]);
    }
    ct1.intt();
    
    let w_approx = az.sub(&ct1);
    let w1_reconstructed = use_hint(&w_approx, &sig.h, 2 * DILITHIUM_GAMMA2);
    
    let c_tilde_check = sha3_256(&[&mu[..], &w1_reconstructed.to_bytes()].concat());
    
    arrays_equal(&sig.c, &c_tilde_check)
}

fn sample_in_ball(seed: &[u8; 32], tau: usize) -> PolynomialRing {
    let mut poly = PolynomialRing::new(DILITHIUM_N, DILITHIUM_Q);
    let mut signs = 0u64;
    
    for i in 0..8 {
        signs |= (seed[i] as u64) << (8 * i);
    }
    
    let mut pos = 8;
    for i in (DILITHIUM_N - tau)..DILITHIUM_N {
        let mut b;
        loop {
            if pos >= 32 {
                break;
            }
            b = seed[pos] as usize;
            pos += 1;
            if b <= i {
                break;
            }
        }
        
        if pos >= 32 {
            break;
        }
        
        poly.coeffs[i] = poly.coeffs[b];
        poly.coeffs[b] = if (signs & 1) == 1 { DILITHIUM_Q - 1 } else { 1 };
        signs >>= 1;
    }
    
    poly
}

fn make_hint(low: &PolynomialVector, high: &PolynomialVector, alpha: u32) -> PolynomialRing {
    let mut hint = PolynomialRing::new(DILITHIUM_N, DILITHIUM_Q);
    
    for k in 0..low.k.min(high.k) {
        for i in 0..DILITHIUM_N {
            let (r1, _) = decompose_single(low.polys[k].coeffs[i], alpha);
            let (s1, _) = decompose_single(high.polys[k].coeffs[i], alpha);
            
            if r1 != s1 && hint.coeffs.iter().filter(|&&x| x == 1).count() < DILITHIUM_OMEGA {
                hint.coeffs[i] = 1;
            }
        }
    }
    
    hint
}

fn use_hint(vector: &PolynomialVector, hint: &PolynomialRing, alpha: u32) -> PolynomialVector {
    let mut result = PolynomialVector::new(vector.k, DILITHIUM_N, DILITHIUM_Q);
    
    for k in 0..vector.k {
        for i in 0..DILITHIUM_N {
            let (mut r1, r0) = decompose_single(vector.polys[k].coeffs[i], alpha);
            
            if hint.coeffs[i] == 1 {
                if r0 > 0 {
                    r1 = (r1 + 1) % ((DILITHIUM_Q - 1) / alpha);
                } else {
                    r1 = if r1 == 0 {
                        (DILITHIUM_Q - 1) / alpha - 1
                    } else {
                        r1 - 1
                    };
                }
            }
            
            result.polys[k].coeffs[i] = r1;
        }
    }
    
    result
}

fn decompose_single(a: u32, alpha: u32) -> (u32, u32) {
    let a1 = (a + 127) >> 7;
    let a1 = if a1 * 1025 + (1 << 21) < DILITHIUM_Q { a1 } else { a1 - 1 };
    let a0 = a - a1 * alpha;
    
    let a0 = if a0 > alpha / 2 { a0 - alpha } else { a0 };
    
    (a1, a0)
}

fn encode_message(msg: &[u8], n: usize, q: u32) -> PolynomialRing {
    let mut poly = PolynomialRing::new(n, q);
    
    for i in 0..(n / 8).min(msg.len()) {
        for j in 0..8 {
            let bit = (msg[i] >> j) & 1;
            poly.coeffs[8 * i + j] = bit as u32 * (q / 2);
        }
    }
    
    poly
}

fn decode_message(poly: &PolynomialRing) -> Vec<u8> {
    let mut msg = vec![0u8; poly.n / 8];
    
    for i in 0..msg.len() {
        for j in 0..8 {
            let bit = if poly.coeffs[8 * i + j] > poly.q / 4 && poly.coeffs[8 * i + j] < 3 * poly.q / 4 {
                1
            } else {
                0
            };
            msg[i] |= bit << j;
        }
    }
    
    msg
}

fn vectors_equal(a: &PolynomialVector, b: &PolynomialVector) -> bool {
    if a.k != b.k {
        return false;
    }
    
    for i in 0..a.k {
        if !polys_equal(&a.polys[i], &b.polys[i]) {
            return false;
        }
    }
    
    true
}

fn polys_equal(a: &PolynomialRing, b: &PolynomialRing) -> bool {
    if a.n != b.n || a.q != b.q {
        return false;
    }
    
    for i in 0..a.n {
        if a.coeffs[i] != b.coeffs[i] {
            return false;
        }
    }
    
    true
}

fn arrays_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

const DILITHIUM_K: usize = 4;
const DILITHIUM_L: usize = 4;
const DILITHIUM_ETA: u32 = 2;
const DILITHIUM_OMEGA: usize = 80;

pub fn test_kyber() -> Result<(), &'static str> {
    let (pk, sk) = kyber_keygen();
    let msg = b"Hello Kyber!";
    let coins = [42u8; 32];
    
    let ct = kyber_encrypt(&pk, msg, &coins);
    let decrypted = kyber_decrypt(&sk, &ct);
    
    if decrypted[..msg.len()] == msg[..] {
        Ok(())
    } else {
        Err("Kyber test failed")
    }
}

pub fn test_dilithium() -> Result<(), &'static str> {
    let (pk, sk) = dilithium_keygen();
    let msg = b"Sign this with Dilithium!";
    
    let sig = dilithium_sign(&sk, msg);
    let valid = dilithium_verify(&pk, msg, &sig);
    
    if valid {
        Ok(())
    } else {
        Err("Dilithium test failed")
    }
}

pub fn test_lattice_crypto() -> Result<(), &'static str> {
    test_kyber()?;
    test_dilithium()?;
    Ok(())
}