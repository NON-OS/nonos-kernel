use crate::crypto::hash::sha256;
use crate::crypto::rng::random_u64;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut private = [0u8; 32];
        for i in 0..4 {
            let rand = random_u64();
            private[i * 8..(i + 1) * 8].copy_from_slice(&rand.to_le_bytes());
        }
        
        // Clamp the private key
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        
        let public = scalar_base_mult(&private);
        
        Self { public, private }
    }
    
    pub fn from_private(private: [u8; 32]) -> Self {
        let mut clamped = private;
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        
        let public = scalar_base_mult(&clamped);
        
        Self {
            public,
            private: clamped,
        }
    }
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[0..32].copy_from_slice(&self.r);
        result[32..64].copy_from_slice(&self.s);
        result
    }
    
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        
        Self { r, s }
    }
}

pub fn sign(keypair: &KeyPair, message: &[u8]) -> Signature {
    // Generate deterministic nonce
    let mut nonce_input = Vec::new();
    nonce_input.extend_from_slice(&keypair.private);
    nonce_input.extend_from_slice(message);
    let nonce_hash = sha256(&nonce_input);
    let nonce = reduce_scalar(&nonce_hash);
    
    // Calculate R = nonce * G
    let r_point = scalar_base_mult(&nonce);
    
    // Calculate h = H(R || A || M)
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&r_point);
    hash_input.extend_from_slice(&keypair.public);
    hash_input.extend_from_slice(message);
    let hash = sha256(&hash_input);
    let h = reduce_scalar(&hash);
    
    // Calculate s = (nonce + h * private_key) mod L
    let s = scalar_add(&nonce, &scalar_mult(&h, &keypair.private));
    
    Signature {
        r: r_point,
        s,
    }
}

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &Signature) -> bool {
    // Check if S is in valid range
    if !is_canonical_scalar(&signature.s) {
        return false;
    }
    
    // Check if R is valid point
    if !is_valid_point(&signature.r) {
        return false;
    }
    
    // Calculate h = H(R || A || M)
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&signature.r);
    hash_input.extend_from_slice(public_key);
    hash_input.extend_from_slice(message);
    let hash = sha256(&hash_input);
    let h = reduce_scalar(&hash);
    
    // Verify: S * G = R + h * A
    let sg = scalar_base_mult(&signature.s);
    let ha = point_mult(&h, public_key);
    let r_plus_ha = point_add(&signature.r, &ha);
    
    constant_time_eq(&sg, &r_plus_ha)
}

// Ed25519 curve operations (simplified implementation)

fn scalar_base_mult(scalar: &[u8; 32]) -> [u8; 32] {
    // Edwards25519 base point
    let base_point = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    ];
    
    point_mult(scalar, &base_point)
}

fn point_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut result = point_identity();
    let mut addend = *point;
    
    for &byte in scalar {
        for bit in 0..8 {
            if (byte >> bit) & 1 != 0 {
                result = point_add(&result, &addend);
            }
            addend = point_double(&addend);
        }
    }
    
    result
}

fn point_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Simplified point addition for Edwards curve
    let mut result = [0u8; 32];
    
    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16;
        result[i] = (sum & 0xFF) as u8;
    }
    
    result
}

fn point_double(point: &[u8; 32]) -> [u8; 32] {
    point_add(point, point)
}

fn point_identity() -> [u8; 32] {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    identity
}

fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u16;
    
    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    
    reduce_scalar(&result)
}

fn scalar_mult(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Simplified scalar multiplication
    let mut result = [0u8; 32];
    
    for i in 0..32 {
        for j in 0..32 {
            if i + j < 32 {
                let prod = (a[i] as u16) * (b[j] as u16);
                let carry = (result[i + j] as u16 + prod) >> 8;
                result[i + j] = ((result[i + j] as u16 + prod) & 0xFF) as u8;
                if i + j + 1 < 32 {
                    result[i + j + 1] = ((result[i + j + 1] as u16 + carry) & 0xFF) as u8;
                }
            }
        }
    }
    
    reduce_scalar(&result)
}

fn reduce_scalar(scalar: &[u8; 32]) -> [u8; 32] {
    // Simplified modular reduction
    let mut result = *scalar;
    
    // Ed25519 order L = 2^252 + 27742317777372353535851937790883648493
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];
    
    // Simple reduction by subtraction
    while scalar_gte(&result, &L) {
        result = scalar_sub(&result, &L);
    }
    
    result
}

fn scalar_gte(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    true // Equal
}

fn scalar_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow = 0i16;
    
    for i in 0..32 {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    
    result
}

fn is_canonical_scalar(s: &[u8; 32]) -> bool {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];
    
    for i in (0..32).rev() {
        if s[i] < L[i] { return true; }
        if s[i] > L[i] { return false; }
    }
    false
}

fn is_valid_point(point: &[u8; 32]) -> bool {
    // Basic validity check for Ed25519 point
    if point.len() != 32 { return false; }
    
    // Check if y coordinate is in valid range
    let y_sign = (point[31] & 0x80) != 0;
    let mut y = *point;
    y[31] &= 0x7F;
    
    // Check if y < p (field prime)
    const P_MINUS_1: [u8; 32] = [
        0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ];
    
    for i in (0..32).rev() {
        if y[i] < P_MINUS_1[i] { return true; }
        if y[i] > P_MINUS_1[i] { return false; }
    }
    
    true
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for i in 0..32 {
        result |= a[i] ^ b[i];
    }
    result == 0
}