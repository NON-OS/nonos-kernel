use alloc::vec::Vec;
use crate::crypto::rng::random_u64;
use crate::crypto::hash::sha256;

const DILITHIUM_Q: u32 = 8380417;
const DILITHIUM_N: usize = 256;
const DILITHIUM_K: usize = 4;
const DILITHIUM_L: usize = 4;
const DILITHIUM_ETA: u32 = 2;
const DILITHIUM_TAU: u32 = 39;
const DILITHIUM_BETA: u32 = 78;
const DILITHIUM_GAMMA1: u32 = 1 << 17;
const DILITHIUM_GAMMA2: u32 = (DILITHIUM_Q - 1) / 88;

#[repr(C)]
pub struct DilithiumPublicKey {
    pub rho: [u8; 32],
    pub t1: [[u32; DILITHIUM_N]; DILITHIUM_K],
}

#[repr(C)]
pub struct DilithiumSecretKey {
    pub rho: [u8; 32],
    pub tr: [u8; 32],
    pub key: [u8; 32],
    pub s1: [[u32; DILITHIUM_N]; DILITHIUM_L],
    pub s2: [[u32; DILITHIUM_N]; DILITHIUM_K],
    pub t0: [[u32; DILITHIUM_N]; DILITHIUM_K],
}

#[repr(C)]
pub struct DilithiumSignature {
    pub c: [u8; 32],
    pub z: [[u32; DILITHIUM_N]; DILITHIUM_L],
    pub h: [[u32; DILITHIUM_N]; DILITHIUM_K],
}

#[repr(C)]
pub struct DilithiumKeyPair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: DilithiumSecretKey,
}

fn mod_q(x: i64) -> u32 {
    let mut result = x % DILITHIUM_Q as i64;
    if result < 0 {
        result += DILITHIUM_Q as i64;
    }
    result as u32
}

fn power2round(r: u32) -> (u32, u32) {
    let r1 = (r + (1 << 12)) >> 13;
    let r0 = r - (r1 << 13);
    (r1, r0)
}

fn decompose(r: u32) -> (u32, u32) {
    let r1 = (r + 127) >> 7;
    let r1 = if r1 > DILITHIUM_Q / 128 {
        r1 - DILITHIUM_Q / 128
    } else {
        r1
    };
    let r0 = r - r1 * 128;
    (r1, r0)
}

fn highbits(r: u32) -> u32 {
    decompose(r).0
}

fn lowbits(r: u32) -> u32 {
    decompose(r).1
}

fn make_hint(z: u32, r: u32) -> bool {
    if z <= DILITHIUM_GAMMA2 || z > DILITHIUM_Q - DILITHIUM_GAMMA2 || 
       (z > DILITHIUM_Q - DILITHIUM_GAMMA2 && r > 0) {
        return false;
    }
    
    highbits(r) != highbits(r + z)
}

fn use_hint(hint: bool, r: u32) -> u32 {
    let (r1, r0) = decompose(r);
    
    if !hint {
        return r1;
    }
    
    if r0 > DILITHIUM_Q / 128 {
        if r1 == 0 {
            DILITHIUM_Q / 128 - 1
        } else {
            r1 - 1
        }
    } else if r1 == DILITHIUM_Q / 128 - 1 {
        0
    } else {
        r1 + 1
    }
}

fn ntt_zetas() -> [u32; 256] {
    let mut zetas = [0u32; 256];
    for i in 0..256 {
        zetas[i] = mod_q(2285 + i as i64 * 17);
    }
    zetas
}

fn ntt(poly: &mut [u32; DILITHIUM_N]) {
    let zetas = ntt_zetas();
    let mut len = 128;
    let mut k = 1;
    
    while len >= 2 {
        let mut start = 0;
        while start < DILITHIUM_N {
            let zeta = zetas[k];
            k += 1;
            
            for j in start..start + len {
                let t = mod_q(zeta as i64 * poly[j + len] as i64);
                poly[j + len] = mod_q(poly[j] as i64 - t as i64);
                poly[j] = mod_q(poly[j] as i64 + t as i64);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

fn invntt(poly: &mut [u32; DILITHIUM_N]) {
    let zetas = ntt_zetas();
    let mut len = 2;
    let mut k = 255;
    
    while len <= 128 {
        let mut start = 0;
        while start < DILITHIUM_N {
            let zeta = zetas[k];
            k -= 1;
            
            for j in start..start + len {
                let t = poly[j];
                poly[j] = mod_q(t as i64 + poly[j + len] as i64);
                poly[j + len] = mod_q(zeta as i64 * (poly[j + len] as i64 - t as i64 + DILITHIUM_Q as i64));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    
    for i in 0..DILITHIUM_N {
        poly[i] = mod_q(poly[i] as i64 * 8347681);
    }
}

fn poly_pointwise_montgomery(a: &[u32; DILITHIUM_N], b: &[u32; DILITHIUM_N]) -> [u32; DILITHIUM_N] {
    let mut result = [0u32; DILITHIUM_N];
    
    for i in 0..DILITHIUM_N {
        result[i] = mod_q(a[i] as i64 * b[i] as i64);
    }
    
    result
}

fn poly_add(a: &[u32; DILITHIUM_N], b: &[u32; DILITHIUM_N]) -> [u32; DILITHIUM_N] {
    let mut result = [0u32; DILITHIUM_N];
    for i in 0..DILITHIUM_N {
        result[i] = mod_q(a[i] as i64 + b[i] as i64);
    }
    result
}

fn poly_sub(a: &[u32; DILITHIUM_N], b: &[u32; DILITHIUM_N]) -> [u32; DILITHIUM_N] {
    let mut result = [0u32; DILITHIUM_N];
    for i in 0..DILITHIUM_N {
        result[i] = mod_q(a[i] as i64 - b[i] as i64);
    }
    result
}

fn poly_chknorm(poly: &[u32; DILITHIUM_N], bound: u32) -> bool {
    for &coeff in poly {
        let centered = if coeff > DILITHIUM_Q / 2 {
            DILITHIUM_Q - coeff
        } else {
            coeff
        };
        
        if centered >= bound {
            return false;
        }
    }
    true
}

fn sample_uniform(seed: &[u8]) -> [u32; DILITHIUM_N] {
    let mut poly = [0u32; DILITHIUM_N];
    let hash = sha256(seed);
    
    for i in 0..DILITHIUM_N {
        let idx = i % 16;
        poly[i] = ((hash[idx * 2] as u32) | ((hash[idx * 2 + 1] as u32) << 8)) % DILITHIUM_Q;
    }
    
    poly
}

fn sample_eta(eta: u32) -> [u32; DILITHIUM_N] {
    let mut poly = [0u32; DILITHIUM_N];
    
    for i in 0..DILITHIUM_N {
        let mut pos = 0i32;
        let mut neg = 0i32;
        
        for _ in 0..eta {
            if random_u64() & 1 == 1 {
                pos += 1;
            } else {
                neg += 1;
            }
        }
        
        poly[i] = mod_q(pos - neg);
    }
    
    poly
}

fn sample_gamma1(gamma1: u32) -> [u32; DILITHIUM_N] {
    let mut poly = [0u32; DILITHIUM_N];
    
    for i in 0..DILITHIUM_N {
        poly[i] = random_u64() as u32 % (2 * gamma1) + DILITHIUM_Q - gamma1;
        poly[i] = mod_q(poly[i] as i64);
    }
    
    poly
}

fn expand_matrix(rho: &[u8; 32]) -> [[u32; DILITHIUM_N]; DILITHIUM_K * DILITHIUM_L] {
    let mut matrix = [[0u32; DILITHIUM_N]; DILITHIUM_K * DILITHIUM_L];
    
    for i in 0..DILITHIUM_K {
        for j in 0..DILITHIUM_L {
            let seed = sha256(&[rho.as_slice(), &[i as u8], &[j as u8]].concat());
            matrix[i * DILITHIUM_L + j] = sample_uniform(&seed);
        }
    }
    
    matrix
}

pub fn dilithium_keygen() -> DilithiumKeyPair {
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    let mut key = [0u8; 32];
    
    for i in 0..32 {
        rho[i] = (random_u64() & 0xFF) as u8;
        sigma[i] = (random_u64() & 0xFF) as u8;
        key[i] = (random_u64() & 0xFF) as u8;
    }
    
    let matrix = expand_matrix(&rho);
    let mut s1 = [[0u32; DILITHIUM_N]; DILITHIUM_L];
    let mut s2 = [[0u32; DILITHIUM_N]; DILITHIUM_K];
    
    for i in 0..DILITHIUM_L {
        s1[i] = sample_eta(DILITHIUM_ETA);
        ntt(&mut s1[i]);
    }
    
    for i in 0..DILITHIUM_K {
        s2[i] = sample_eta(DILITHIUM_ETA);
        ntt(&mut s2[i]);
    }
    
    let mut t = [[0u32; DILITHIUM_N]; DILITHIUM_K];
    for i in 0..DILITHIUM_K {
        let mut temp = [0u32; DILITHIUM_N];
        for j in 0..DILITHIUM_L {
            let mul_result = poly_pointwise_montgomery(&matrix[i * DILITHIUM_L + j], &s1[j]);
            temp = poly_add(&temp, &mul_result);
        }
        invntt(&mut temp);
        t[i] = poly_add(&temp, &s2[i]);
    }
    
    let mut t1 = [[0u32; DILITHIUM_N]; DILITHIUM_K];
    let mut t0 = [[0u32; DILITHIUM_N]; DILITHIUM_K];
    
    for i in 0..DILITHIUM_K {
        for j in 0..DILITHIUM_N {
            let (t1_val, t0_val) = power2round(t[i][j]);
            t1[i][j] = t1_val;
            t0[i][j] = t0_val;
        }
    }
    
    let tr = sha256(&[&rho[..], &serialize_t1(&t1)[..]].concat());
    
    DilithiumKeyPair {
        public_key: DilithiumPublicKey { rho, t1 },
        secret_key: DilithiumSecretKey { rho, tr, key, s1, s2, t0 },
    }
}

pub fn dilithium_sign(message: &[u8], secret_key: &DilithiumSecretKey) -> DilithiumSignature {
    let mu = sha256(&[&secret_key.tr[..], message].concat());
    
    let mut nonce = 0u16;
    loop {
        let y = sample_gamma1_with_nonce(&secret_key.key, &mu, nonce);
        let matrix = expand_matrix(&secret_key.rho);
        
        let mut w = [[0u32; DILITHIUM_N]; DILITHIUM_K];
        for i in 0..DILITHIUM_K {
            let mut temp = [0u32; DILITHIUM_N];
            for j in 0..DILITHIUM_L {
                let mul_result = poly_pointwise_montgomery(&matrix[i * DILITHIUM_L + j], &y[j]);
                temp = poly_add(&temp, &mul_result);
            }
            invntt(&mut temp);
            w[i] = temp;
        }
        
        let mut w1 = [[0u32; DILITHIUM_N]; DILITHIUM_K];
        for i in 0..DILITHIUM_K {
            for j in 0..DILITHIUM_N {
                w1[i][j] = highbits(w[i][j]);
            }
        }
        
        let c_seed = sha256(&[&mu[..], &serialize_w1(&w1)[..]].concat());
        let c = sample_in_ball(&c_seed);
        
        let mut z = [[0u32; DILITHIUM_N]; DILITHIUM_L];
        for i in 0..DILITHIUM_L {
            let mut temp_s1 = secret_key.s1[i];
            invntt(&mut temp_s1);
            let cs1 = poly_pointwise_montgomery(&c, &temp_s1);
            z[i] = poly_add(&y[i], &cs1);
        }
        
        let mut valid = true;
        for i in 0..DILITHIUM_L {
            if !poly_chknorm(&z[i], DILITHIUM_GAMMA1 - DILITHIUM_BETA) {
                valid = false;
                break;
            }
        }
        
        if !valid {
            nonce += 1;
            continue;
        }
        
        let mut h = [[0u32; DILITHIUM_N]; DILITHIUM_K];
        for i in 0..DILITHIUM_K {
            let mut temp_s2 = secret_key.s2[i];
            invntt(&mut temp_s2);
            let cs2 = poly_pointwise_montgomery(&c, &temp_s2);
            let r = poly_sub(&w[i], &cs2);
            
            for j in 0..DILITHIUM_N {
                h[i][j] = if make_hint(lowbits(r[j]), w[i][j]) { 1 } else { 0 };
            }
        }
        
        return DilithiumSignature { c: c_seed, z, h };
    }
}

pub fn dilithium_verify(message: &[u8], signature: &DilithiumSignature, public_key: &DilithiumPublicKey) -> bool {
    let mu = sha256(&[&public_key.rho[..], message].concat());
    let c = sample_in_ball(&signature.c);
    
    for i in 0..DILITHIUM_L {
        if !poly_chknorm(&signature.z[i], DILITHIUM_GAMMA1 - DILITHIUM_BETA) {
            return false;
        }
    }
    
    let matrix = expand_matrix(&public_key.rho);
    let mut w1_prime = [[0u32; DILITHIUM_N]; DILITHIUM_K];
    
    for i in 0..DILITHIUM_K {
        let mut temp = [0u32; DILITHIUM_N];
        for j in 0..DILITHIUM_L {
            let mul_result = poly_pointwise_montgomery(&matrix[i * DILITHIUM_L + j], &signature.z[j]);
            temp = poly_add(&temp, &mul_result);
        }
        invntt(&mut temp);
        
        let mut t1_ntt = public_key.t1[i];
        ntt(&mut t1_ntt);
        let ct1 = poly_pointwise_montgomery(&c, &t1_ntt);
        invntt(&mut ct1);
        
        let w_approx = poly_sub(&temp, &ct1);
        
        for j in 0..DILITHIUM_N {
            w1_prime[i][j] = use_hint(signature.h[i][j] == 1, w_approx[j]);
        }
    }
    
    let c_prime = sha256(&[&mu[..], &serialize_w1(&w1_prime)[..]].concat());
    
    signature.c == c_prime
}

fn sample_gamma1_with_nonce(key: &[u8; 32], mu: &[u8; 32], nonce: u16) -> [[u32; DILITHIUM_N]; DILITHIUM_L] {
    let mut y = [[0u32; DILITHIUM_N]; DILITHIUM_L];
    
    for i in 0..DILITHIUM_L {
        let seed = sha256(&[key.as_slice(), mu.as_slice(), &nonce.to_le_bytes(), &[i as u8]].concat());
        y[i] = sample_gamma1_from_seed(&seed);
    }
    
    y
}

fn sample_gamma1_from_seed(seed: &[u8; 32]) -> [u32; DILITHIUM_N] {
    let mut poly = [0u32; DILITHIUM_N];
    
    for i in 0..DILITHIUM_N {
        let idx = i % 16;
        let val = ((seed[idx * 2] as u32) | ((seed[idx * 2 + 1] as u32) << 8)) % (2 * DILITHIUM_GAMMA1);
        poly[i] = mod_q(val as i64 + DILITHIUM_Q as i64 - DILITHIUM_GAMMA1 as i64);
    }
    
    poly
}

fn sample_in_ball(seed: &[u8; 32]) -> [u32; DILITHIUM_N] {
    let mut poly = [0u32; DILITHIUM_N];
    let mut signs = 0u64;
    
    for i in 0..8 {
        signs |= (seed[i] as u64) << (i * 8);
    }
    
    for i in 0..DILITHIUM_TAU as usize {
        let pos = (seed[8 + i % 24] as usize * 256 + seed[8 + (i + 1) % 24] as usize) % DILITHIUM_N;
        poly[pos] = if (signs >> i) & 1 == 1 { 1 } else { DILITHIUM_Q - 1 };
    }
    
    poly
}

fn serialize_t1(t1: &[[u32; DILITHIUM_N]; DILITHIUM_K]) -> Vec<u8> {
    let mut result = Vec::new();
    
    for i in 0..DILITHIUM_K {
        for j in 0..DILITHIUM_N {
            result.extend_from_slice(&t1[i][j].to_le_bytes());
        }
    }
    
    result
}

fn serialize_w1(w1: &[[u32; DILITHIUM_N]; DILITHIUM_K]) -> Vec<u8> {
    let mut result = Vec::new();
    
    for i in 0..DILITHIUM_K {
        for j in 0..DILITHIUM_N {
            result.extend_from_slice(&w1[i][j].to_le_bytes());
        }
    }
    
    result
}