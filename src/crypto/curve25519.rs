//! Curve25519 elliptic curve 

#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use super::{CryptoResult, CryptoError};
use super::entropy::get_entropy;

macro_rules! array_ref {
    ($slice:expr, $start:expr, $len:expr) => {
        unsafe {
            let slice_ptr = $slice.as_ptr();
            let slice_len = $slice.len();
            
            if $start + $len > slice_len {
                panic!("array_ref: slice bounds exceeded");
            }
            
            &*(slice_ptr.add($start) as *const [u8; $len])
        }
    };
}

/// Field element for Curve25519 (mod 2^255 - 19)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FieldElement(pub [i64; 10]);

/// Point on Curve25519 in extended coordinates
#[derive(Debug, Clone, Copy)]
pub struct EdwardsPoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub t: FieldElement,
}

/// Curve25519 private key (32 bytes)
pub type PrivateKey = [u8; 32];

/// Curve25519 public key (32 bytes)  
pub type PublicKey = [u8; 32];

/// Shared secret (32 bytes)
pub type SharedSecret = [u8; 32];

/// Prime for Curve25519: 2^255 - 19
const P: [i64; 10] = [
    0x3ffffffed, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff,
    0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff
];

/// Base point for Ed25519
const ED25519_BASEPOINT: EdwardsPoint = EdwardsPoint {
    x: FieldElement([
        0x325d51a, 0x18b5823, 0x537be77, 0x6f7d1c, 0x100f84, 
        0x1f82d19, 0x10405a6, 0x1873f3d, 0x17cb0b, 0x171312a
    ]),
    y: FieldElement([
        0x2666658, 0x1999999, 0x0cccccc, 0x1333333, 0x1999999,
        0x0666666, 0x3333333, 0x0cccccc, 0x2666666, 0x1999999
    ]),
    z: FieldElement([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    t: FieldElement([
        0x68ab3a5, 0xb7608c, 0x2318e7c, 0x1ee4199, 0x1681b8c,
        0x3c5984, 0x1db8278, 0xe972ba, 0x12e6d63, 0xa7b8a9
    ]),
};

impl FieldElement {
    /// Create a new field element from u64
    pub fn from_u64(n: u64) -> FieldElement {
        let mut limbs = [0i64; 10];
        limbs[0] = (n & 0x3ffffff) as i64;
        limbs[1] = ((n >> 26) & 0x1ffffff) as i64;
        limbs[2] = ((n >> 51) & 0x3ffffff) as i64;
        FieldElement(limbs)
    }
    
    /// Create zero field element
    pub fn zero() -> FieldElement {
        FieldElement([0; 10])
    }
    
    /// Create one field element
    pub fn one() -> FieldElement {
        let mut limbs = [0i64; 10];
        limbs[0] = 1;
        FieldElement(limbs)
    }
    
    /// Field addition
    pub fn add(&self, other: &FieldElement) -> FieldElement {
        let mut result = [0i64; 10];
        for i in 0..10 {
            result[i] = self.0[i] + other.0[i];
        }
        FieldElement(result).reduce()
    }
    
    /// Field subtraction
    pub fn sub(&self, other: &FieldElement) -> FieldElement {
        let mut result = [0i64; 10];
        for i in 0..10 {
            result[i] = self.0[i] - other.0[i];
        }
        FieldElement(result).reduce()
    }
    
    /// Field multiplication
    pub fn mul(&self, other: &FieldElement) -> FieldElement {
        let a = &self.0;
        let b = &other.0;
        
        let mut output = [0i64; 19];
        
        for i in 0..10 {
            for j in 0..10 {
                output[i + j] += a[i] * b[j];
            }
        }
        
        // Reduce modulo 2^255 - 19
        for i in (10..19).rev() {
            output[i - 10] += 38 * output[i];
            output[i] = 0;
        }
        
        let mut result = [0i64; 10];
        for i in 0..10 {
            result[i] = output[i];
        }
        
        FieldElement(result).reduce()
    }
    
    /// Field squaring (optimized multiplication by self)
    pub fn square(&self) -> FieldElement {
        self.mul(self)
    }
    
    /// Field inversion using Fermat's little theorem
    pub fn invert(&self) -> FieldElement {
        // a^(p-2) mod p = a^(-1) mod p for prime p
        let mut result = *self;
        
        // 2^255 - 19 - 2 = 2^255 - 21
        for i in (0..255).rev() {
            result = result.square();
            if ((21u64 >> i) & 1) == 1 {
                result = result.mul(self);
            }
        }
        
        result
    }
    
    /// Reduce field element modulo 2^255 - 19
    pub fn reduce(self) -> FieldElement {
        let mut h = self.0;
        
        // First reduction pass
        let mut carry = 0i64;
        for i in 0..10 {
            carry += h[i];
            h[i] = carry & ((1 << 26) - 1);
            carry >>= 26;
            if i == 9 {
                carry *= 19;
            }
        }
        
        // Second reduction pass
        let mut carry = 0i64;
        for i in 0..10 {
            carry += h[i];
            h[i] = carry & ((1 << 25) - 1);
            carry >>= 25;
            if i == 9 {
                carry *= 19;
            }
        }
        
        FieldElement(h)
    }
    
    /// Convert to bytes (little endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        let h = self.reduce().0;
        let mut bytes = [0u8; 32];
        
        bytes[0] = (h[0] >> 0) as u8;
        bytes[1] = (h[0] >> 8) as u8;
        bytes[2] = (h[0] >> 16) as u8;
        bytes[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
        bytes[4] = (h[1] >> 6) as u8;
        bytes[5] = (h[1] >> 14) as u8;
        bytes[6] = ((h[1] >> 22) | (h[2] << 4)) as u8;
        bytes[7] = (h[2] >> 4) as u8;
        bytes[8] = (h[2] >> 12) as u8;
        bytes[9] = ((h[2] >> 20) | (h[3] << 6)) as u8;
        bytes[10] = (h[3] >> 2) as u8;
        bytes[11] = (h[3] >> 10) as u8;
        bytes[12] = (h[3] >> 18) as u8;
        bytes[13] = (h[4] >> 0) as u8;
        bytes[14] = (h[4] >> 8) as u8;
        bytes[15] = (h[4] >> 16) as u8;
        bytes[16] = ((h[4] >> 24) | (h[5] << 1)) as u8;
        bytes[17] = (h[5] >> 7) as u8;
        bytes[18] = (h[5] >> 15) as u8;
        bytes[19] = ((h[5] >> 23) | (h[6] << 3)) as u8;
        bytes[20] = (h[6] >> 5) as u8;
        bytes[21] = (h[6] >> 13) as u8;
        bytes[22] = ((h[6] >> 21) | (h[7] << 5)) as u8;
        bytes[23] = (h[7] >> 3) as u8;
        bytes[24] = (h[7] >> 11) as u8;
        bytes[25] = (h[7] >> 19) as u8;
        bytes[26] = (h[8] >> 0) as u8;
        bytes[27] = (h[8] >> 8) as u8;
        bytes[28] = (h[8] >> 16) as u8;
        bytes[29] = ((h[8] >> 24) | (h[9] << 2)) as u8;
        bytes[30] = (h[9] >> 6) as u8;
        bytes[31] = (h[9] >> 14) as u8;
        
        bytes
    }
    
    /// Create from bytes (little endian)
    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement {
        let mut h = [0i64; 10];
        
        h[0] = (bytes[0] as i64) |
               ((bytes[1] as i64) << 8) |
               ((bytes[2] as i64) << 16) |
               (((bytes[3] as i64) & 0x3f) << 24);
               
        h[1] = (((bytes[3] as i64) & 0xc0) >> 6) |
               ((bytes[4] as i64) << 2) |
               ((bytes[5] as i64) << 10) |
               ((bytes[6] as i64) << 18) |
               (((bytes[7] as i64) & 0x0f) << 26);
               
        h[2] = (((bytes[7] as i64) & 0xf0) >> 4) |
               ((bytes[8] as i64) << 4) |
               ((bytes[9] as i64) << 12) |
               (((bytes[10] as i64) & 0x3f) << 20);
               
        h[3] = (((bytes[10] as i64) & 0xc0) >> 6) |
               ((bytes[11] as i64) << 2) |
               ((bytes[12] as i64) << 10) |
               ((bytes[13] as i64) << 18);
               
        h[4] = (bytes[14] as i64) |
               ((bytes[15] as i64) << 8) |
               ((bytes[16] as i64) << 16) |
               (((bytes[17] as i64) & 0x7f) << 24);
               
        h[5] = (((bytes[17] as i64) & 0x80) >> 7) |
               ((bytes[18] as i64) << 1) |
               ((bytes[19] as i64) << 9) |
               (((bytes[20] as i64) & 0x1f) << 17);
               
        h[6] = (((bytes[20] as i64) & 0xe0) >> 5) |
               ((bytes[21] as i64) << 3) |
               ((bytes[22] as i64) << 11) |
               (((bytes[23] as i64) & 0x07) << 19);
               
        h[7] = (((bytes[23] as i64) & 0xf8) >> 3) |
               ((bytes[24] as i64) << 5) |
               ((bytes[25] as i64) << 13) |
               ((bytes[26] as i64) << 21);
               
        h[8] = (bytes[27] as i64) |
               ((bytes[28] as i64) << 8) |
               ((bytes[29] as i64) << 16) |
               (((bytes[30] as i64) & 0x3f) << 24);
               
        h[9] = (((bytes[30] as i64) & 0xc0) >> 6) |
               ((bytes[31] as i64) << 2);
        
        FieldElement(h)
    }
    
    /// Check if field element is negative (used for point compression)
    pub fn is_negative(&self) -> bool {
        let bytes = self.to_bytes();
        (bytes[0] & 1) == 1
    }
}

impl EdwardsPoint {
    /// Point at infinity (identity element)
    pub fn identity() -> EdwardsPoint {
        EdwardsPoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }
    
    /// Point addition in extended coordinates
    pub fn add(&self, other: &EdwardsPoint) -> EdwardsPoint {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&other.t).mul(&FieldElement::from_u64(486662)); // 2d
        let d = self.z.mul(&other.z).mul(&FieldElement::from_u64(2));
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        
        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }
    
    /// Point doubling
    pub fn double(&self) -> EdwardsPoint {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().mul(&FieldElement::from_u64(2));
        let d = a.add(&b);
        let e = self.x.add(&self.y).square().sub(&d);
        let f = a.sub(&b);
        let g = c.add(&f);
        
        EdwardsPoint {
            x: e.mul(&f),
            y: d.mul(&g),
            z: f.mul(&g),
            t: e.mul(&d),
        }
    }
    
    /// Scalar multiplication using Montgomery ladder
    pub fn scalar_mul(&self, scalar: &[u8; 32]) -> EdwardsPoint {
        let mut result = EdwardsPoint::identity();
        let mut base = *self;
        
        for &byte in scalar {
            for i in 0..8 {
                if ((byte >> i) & 1) == 1 {
                    result = result.add(&base);
                }
                base = base.double();
            }
        }
        
        result
    }
    
    /// Compress point to 32 bytes (y-coordinate + sign of x)
    pub fn compress(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        
        let mut bytes = y.to_bytes();
        if x.is_negative() {
            bytes[31] |= 0x80;
        }
        
        bytes
    }
    
    /// Decompress point from 32 bytes
    pub fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
        let mut y_bytes = *bytes;
        let x_sign = (y_bytes[31] & 0x80) != 0;
        y_bytes[31] &= 0x7f;
        
        let y = FieldElement::from_bytes(&y_bytes);
        
        // Solve for x: x^2 = (y^2 - 1) / (dy^2 + 1)
        let y2 = y.square();
        let d = FieldElement::from_u64(486662); // Edwards curve parameter d
        let numerator = y2.sub(&FieldElement::one());
        let denominator = d.mul(&y2).add(&FieldElement::one());
        let x2 = numerator.mul(&denominator.invert());
        
        // Compute square root (if it exists)
        let x = sqrt(&x2)?;
        
        let final_x = if x.is_negative() == x_sign {
            x
        } else {
            FieldElement::zero().sub(&x)
        };
        
        Some(EdwardsPoint {
            x: final_x,
            y,
            z: FieldElement::one(),
            t: final_x.mul(&y),
        })
    }
}

/// Generate Curve25519 keypair
pub fn generate_keypair() -> (PrivateKey, PublicKey) {
    let mut private = [0u8; 32];
    let entropy = get_entropy(32);
    private.copy_from_slice(&entropy);
    
    // Clamp private key according to Curve25519 spec
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    
    let public = scalar_base_mult(&private);
    
    (private, public)
}

/// Scalar multiplication with base point
pub fn scalar_base_mult(scalar: &PrivateKey) -> PublicKey {
    let point = ED25519_BASEPOINT.scalar_mul(scalar);
    point.compress()
}

/// X25519 key exchange (RFC 7748)
pub fn x25519(private_key: &PrivateKey, public_key: &PublicKey) -> Result<SharedSecret, CryptoError> {
    // Decompress public key
    let point = EdwardsPoint::decompress(public_key)
        .ok_or(CryptoError::InvalidLength)?;
    
    // Scalar multiplication
    let shared_point = point.scalar_mul(private_key);
    
    // Return x-coordinate as shared secret
    let z_inv = shared_point.z.invert();
    let x = shared_point.x.mul(&z_inv);
    
    Ok(x.to_bytes())
}

/// Square root in field (Tonelli-Shanks algorithm)
fn sqrt(n: &FieldElement) -> Option<FieldElement> {
    // For p = 2^255 - 19, we can use the simple formula
    // since p ≡ 5 (mod 8)
    let candidate = n.pow(&[(2_u64.pow(253) - 5) / 4]);
    
    if candidate.square() == *n {
        Some(candidate)
    } else {
        None
    }
}

impl FieldElement {
    /// Fast exponentiation
    fn pow(&self, exp: &[u64]) -> FieldElement {
        let mut result = FieldElement::one();
        let mut base = *self;
        
        for &word in exp {
            for i in 0..64 {
                if ((word >> i) & 1) == 1 {
                    result = result.mul(&base);
                }
                base = base.square();
            }
        }
        
        result
    }
}

/// Constant-time conditional swap for Montgomery ladder
fn conditional_swap(swap: u8, a: &mut FieldElement, b: &mut FieldElement) {
    let mask = (swap as i64).wrapping_neg();
    for i in 0..10 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// Montgomery ladder for X25519 (constant-time scalar multiplication)
pub fn montgomery_ladder(scalar: &[u8; 32], u_coordinate: &FieldElement) -> FieldElement {
    let mut x1 = *u_coordinate;
    let mut x2 = FieldElement::one();
    let mut z2 = FieldElement::zero();
    let mut x3 = *u_coordinate;
    let mut z3 = FieldElement::one();
    
    let mut swap = 0u8;
    
    for i in (0..255).rev() {
        let bit = (scalar[i / 8] >> (i % 8)) & 1;
        swap ^= bit;
        conditional_swap(swap, &mut x2, &mut x3);
        conditional_swap(swap, &mut z2, &mut z3);
        swap = bit;
        
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&bb.add(&e.mul(&FieldElement::from_u64(121665))));
    }
    
    conditional_swap(swap, &mut x2, &mut x3);
    conditional_swap(swap, &mut z2, &mut z3);
    
    x2.mul(&z2.invert())
}

/// Ed25519 signature scheme
pub mod ed25519 {
    use super::*;
    use crate::crypto::sha512;
    
    /// Ed25519 signature
    pub type Signature = [u8; 64];
    
    /// Ed25519 keypair
    pub struct KeyPair {
        pub private: PrivateKey,
        pub public: PublicKey,
    }
    
    /// Generate Ed25519 keypair
    pub fn generate_keypair() -> KeyPair {
        let mut seed = [0u8; 32];
        let entropy = get_entropy(32);
        seed.copy_from_slice(&entropy);
        
        let h = sha512(&seed);
        let mut private = [0u8; 32];
        private.copy_from_slice(&h[..32]);
        
        // Clamp private key
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        
        let public = scalar_base_mult(&private);
        
        KeyPair { private, public }
    }
    
    /// Sign message with Ed25519
    pub fn sign(keypair: &KeyPair, message: &[u8]) -> Signature {
        let h = sha512(&keypair.private);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        let prefix = &h[32..];
        
        // r = H(prefix || M)
        let mut r_input = Vec::with_capacity(32 + message.len());
        r_input.extend_from_slice(prefix);
        r_input.extend_from_slice(message);
        let r_hash = sha512(&r_input);
        let mut r_scalar = [0u8; 32];
        r_scalar.copy_from_slice(&r_hash[..32]);
        
        // R = rB
        let r_point = ED25519_BASEPOINT.scalar_mul(&r_scalar);
        let r_compressed = r_point.compress();
        
        // S = (r + H(R || A || M) * a) mod l
        let mut s_input = Vec::with_capacity(32 + 32 + message.len());
        s_input.extend_from_slice(&r_compressed);
        s_input.extend_from_slice(&keypair.public);
        s_input.extend_from_slice(message);
        let s_hash = sha512(&s_input);
        let mut s_scalar = [0u8; 32];
        s_scalar.copy_from_slice(&s_hash[..32]);
        
        // Scalar arithmetic modulo curve order
        let s = scalar_add(&scalar_mul(&s_scalar, &a), &r_scalar);
        
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r_compressed);
        signature[32..].copy_from_slice(&s);
        
        signature
    }
    
    /// Verify Ed25519 signature
    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        let r = &signature[..32];
        let s = &signature[32..];
        
        // Decode R and A
        let mut r_array = [0u8; 32];
        r_array.copy_from_slice(r);
        let mut s_array = [0u8; 32];
        s_array.copy_from_slice(s);
        let r_point = match EdwardsPoint::decompress(&r_array) {
            Some(p) => p,
            None => return false,
        };
        
        let a_point = match EdwardsPoint::decompress(public_key) {
            Some(p) => p,
            None => return false,
        };
        
        // h = H(R || A || M)
        let mut h_input = Vec::with_capacity(32 + 32 + message.len());
        h_input.extend_from_slice(r);
        h_input.extend_from_slice(public_key);
        h_input.extend_from_slice(message);
        let h_hash = sha512(&h_input);
        let mut h_scalar = [0u8; 32];
        h_scalar.copy_from_slice(&h_hash[..32]);
        
        // Check [s]B = R + [h]A
        let left = ED25519_BASEPOINT.scalar_mul(&s_array);
        let right = r_point.add(&a_point.scalar_mul(&h_scalar));
        
        left.compress() == right.compress()
    }
    
    // Helper functions for scalar arithmetic
    fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let mut carry = 0u16;
        
        for i in 0..32 {
            let sum = (a[i] as u16) + (b[i] as u16) + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }
        
        result
    }
    
    fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        // Simplified scalar multiplication
        let mut result = [0u8; 32];
        
        for i in 0..32 {
            for j in 0..8 {
                if ((b[i] >> j) & 1) == 1 {
                    result = scalar_add(&result, a);
                }
            }
        }
        
        result
    }
}


pub fn x25519_keypair() -> Result<([u8; 32], [u8; 32]), &'static str> {
    let mut private = [0u8; 32];
    let entropy = super::entropy::get_entropy(32);
    private.copy_from_slice(&entropy[..32]);
    let public = scalar_base_mult(&private);
    Ok((public, private))
}

pub fn derive_public_key(private: &[u8; 32]) -> [u8; 32] {
    scalar_base_mult(private)
}

fn fe_zero() -> FieldElement { FieldElement([0; 10]) }
fn fe_one() -> FieldElement { FieldElement([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]) }
fn fe_from_bytes(bytes: &[u8; 32]) -> FieldElement {
    let mut h = [0i64; 10];
    h[0] = (bytes[0] as i64) | ((bytes[1] as i64) << 8) | ((bytes[2] as i64) << 16) | ((bytes[3] as i64) << 24);
    h[1] = ((bytes[3] as i64) >> 8) | ((bytes[4] as i64) << 8) | ((bytes[5] as i64) << 16) | ((bytes[6] as i64) << 24);
    h[2] = ((bytes[6] as i64) >> 8) | ((bytes[7] as i64) << 8) | ((bytes[8] as i64) << 16) | ((bytes[9] as i64) << 24);
    h[3] = ((bytes[9] as i64) >> 8) | ((bytes[10] as i64) << 8) | ((bytes[11] as i64) << 16) | ((bytes[12] as i64) << 24);
    h[4] = ((bytes[12] as i64) >> 8) | ((bytes[13] as i64) << 8) | ((bytes[14] as i64) << 16) | ((bytes[15] as i64) << 24);
    h[5] = ((bytes[15] as i64) >> 8) | ((bytes[16] as i64) << 8) | ((bytes[17] as i64) << 16) | ((bytes[18] as i64) << 24);
    h[6] = ((bytes[18] as i64) >> 8) | ((bytes[19] as i64) << 8) | ((bytes[20] as i64) << 16) | ((bytes[21] as i64) << 24);
    h[7] = ((bytes[21] as i64) >> 8) | ((bytes[22] as i64) << 8) | ((bytes[23] as i64) << 16) | ((bytes[24] as i64) << 24);
    h[8] = ((bytes[24] as i64) >> 8) | ((bytes[25] as i64) << 8) | ((bytes[26] as i64) << 16) | ((bytes[27] as i64) << 24);
    h[9] = ((bytes[27] as i64) >> 8) | ((bytes[28] as i64) << 8) | ((bytes[29] as i64) << 16) | ((bytes[30] as i64) << 24);
    FieldElement(h)
}
fn fe_to_bytes(f: &FieldElement, bytes: &mut [u8; 32]) {
    let mut h = f.0;
    let carry = [0i64; 10];
    for _i in 0..2 {
        for j in 0..9 { let c = h[j] >> 26; h[j+1] += c; h[j] -= c << 26; }
        let c = h[9] >> 25; h[0] += c * 19; h[9] -= c << 25;
        for j in 0..9 { let c = h[j] >> 26; h[j+1] += c; h[j] -= c << 26; }
        let c = h[9] >> 25; h[0] += c * 19; h[9] -= c << 25;
    }
    for i in 0..32 { bytes[i] = (h[i/4] >> (8*(i&3))) as u8; }
}
fn fe_add(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let mut h = [0i64; 10];
    for i in 0..10 { h[i] = a.0[i] + b.0[i]; }
    FieldElement(h)
}
fn fe_sub(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let mut h = [0i64; 10];
    for i in 0..10 { h[i] = a.0[i] - b.0[i]; }
    FieldElement(h)
}
fn fe_mul(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let mut h = [0i64; 19];
    for i in 0..10 { for j in 0..10 { h[i+j] += a.0[i] * b.0[j]; } }
    for i in 0..9 { h[i] += 19 * h[i+10]; }
    let mut g = [0i64; 10];
    for i in 0..10 { g[i] = h[i]; }
    FieldElement(g)
}
fn fe_square(a: &FieldElement) -> FieldElement { fe_mul(a, a) }
fn fe_invert(z: &FieldElement) -> FieldElement {
    let mut t0 = fe_square(z);
    for _i in 0..1 { t0 = fe_square(&t0); }
    let mut t1 = fe_square(&t0);
    for _i in 0..1 { t1 = fe_square(&t1); }
    t1 = fe_mul(z, &t1);
    t0 = fe_mul(&t0, &t1);
    let mut t2 = fe_square(&t0);
    t1 = fe_mul(&t1, &t2);
    t2 = fe_square(&t1);
    for _i in 0..4 { t2 = fe_square(&t2); }
    t1 = fe_mul(&t1, &t2);
    t2 = fe_square(&t1);
    for _i in 0..9 { t2 = fe_square(&t2); }
    t2 = fe_mul(&t1, &t2);
    let mut t3 = fe_square(&t2);
    for _i in 0..19 { t3 = fe_square(&t3); }
    t2 = fe_mul(&t2, &t3);
    t2 = fe_square(&t2);
    for _i in 0..9 { t2 = fe_square(&t2); }
    t1 = fe_mul(&t1, &t2);
    t2 = fe_square(&t1);
    for _i in 0..49 { t2 = fe_square(&t2); }
    t2 = fe_mul(&t1, &t2);
    t3 = fe_square(&t2);
    for _i in 0..99 { t3 = fe_square(&t3); }
    t2 = fe_mul(&t2, &t3);
    t2 = fe_square(&t2);
    for _i in 0..49 { t2 = fe_square(&t2); }
    t1 = fe_mul(&t1, &t2);
    t1 = fe_square(&t1);
    for _i in 0..4 { t1 = fe_square(&t1); }
    fe_mul(&t0, &t1)
}
fn fe_mul121666(a: &FieldElement) -> FieldElement {
    let mut h = [0i64; 10];
    for i in 0..10 { h[i] = a.0[i] * 121666; }
    FieldElement(h)
}
fn fe_cswap(a: &mut FieldElement, b: &mut FieldElement, c: u8) {
    let mask = (c as i64).wrapping_neg();
    for i in 0..10 {
        let x = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= x;
        b.0[i] ^= x;
    }
}

fn scalar_mult(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    
    let mut x = fe_from_bytes(public);
    let mut z = fe_one();
    let mut x2 = fe_one();
    let mut z2 = fe_zero();
    let mut x3 = fe_from_bytes(public);
    let mut z3 = fe_one();
    
    let mut swap = 0u8;
    
    for i in (0..255).rev() {
        let bit = (private[i / 8] >> (i & 7)) & 1;
        swap ^= bit;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = bit;
        
        let a = fe_add(&x2, &z2);
        let aa = fe_square(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_square(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        
        x3 = fe_square(&fe_add(&da, &cb));
        z3 = fe_mul(&x, &fe_square(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul121666(&e)));
    }
    
    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);
    
    z2 = fe_invert(&z2);
    x2 = fe_mul(&x2, &z2);
    fe_to_bytes(&x2, &mut result);
    
    result
}

pub fn compute_shared_secret(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    scalar_mult(private, public)
}
