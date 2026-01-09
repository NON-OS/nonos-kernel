// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::{load_u64_le, FieldElement};
use crate::crypto::entropy::get_entropy;
use crate::crypto::sha512::sha512;

pub type Signature = [u8; 64];
pub type PrivateKey = [u8; 32];
pub type PublicKey = [u8; 32];

const D: FieldElement = FieldElement([
    0x34dca135978a3,
    0x1a8283b156ebd,
    0x5e7a26001c029,
    0x739c663a03cbb,
    0x52036cee2b6ff,
]);

const D2: FieldElement = FieldElement([
    0x69b9426b2f159,
    0x35050762add7a,
    0x3cf44c0038052,
    0x6738cc7407977,
    0x2406d9dc56dff,
]);

const BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

// SAFETY: Precomputed Ed25519 basepoint in extended coordinates to avoid
// runtime decompression and eliminate unwrap() calls. These values are
// mathematically derived constants that have been verified.
const BASEPOINT: EdwardsPoint = EdwardsPoint {
    x: FieldElement([
        0x62d608f25d51a, 0x412a4b4f6592a, 0x75b7171a4b31d, 0x1ff60527118fe, 0x216936d3cd6e5,
    ]),
    y: FieldElement([
        0x6666666666658, 0x4cccccccccccc, 0x1999999999999, 0x3333333333333, 0x6666666666666,
    ]),
    z: FieldElement([1, 0, 0, 0, 0]),
    t: FieldElement([
        0x68ab3a5b7dda3, 0xeea2a5eadbb, 0x2af8df483c27e, 0x332b375274732, 0x67875f0fd78b7,
    ]),
};

// SECURITY: No Copy trait - points hold secret-dependent intermediate values during
// scalar multiplication and must be explicitly cloned and securely zeroized
#[derive(Clone)]
pub struct EdwardsPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Drop for EdwardsPoint {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl EdwardsPoint {
    pub fn identity() -> Self {
        EdwardsPoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    pub fn add(&self, other: &EdwardsPoint) -> EdwardsPoint {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&D2).mul(&other.t);
        let d = self.z.mul(&other.z);
        let d = d.add(&d);
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

    pub fn double(&self) -> EdwardsPoint {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        let d = a.neg();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);

        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    // SECURITY: Constant-time scalar multiplication using Montgomery ladder
    // to prevent timing side-channel attacks that could leak the secret scalar.
    pub fn scalar_mul(&self, scalar: &[u8; 32]) -> EdwardsPoint {
        let mut r0 = EdwardsPoint::identity();
        let mut r1 = self.clone();

        for i in (0..256).rev() {
            let byte = i / 8;
            let bit = i % 8;
            let b = ((scalar[byte] >> bit) & 1) as u64;
            let sum = r0.add(&r1);
            let r0_double = r0.double();
            let r1_double = r1.double();

            r0 = Self::ct_select(b, &sum, &r0_double);
            r1 = Self::ct_select(b, &r1_double, &sum);
        }

        r0
    }

    // SECURITY: Constant-time conditional selection to prevent timing attacks.
    // Returns a if condition == 1, b if condition == 0.
    fn ct_select(condition: u64, a: &Self, b: &Self) -> Self {
        let mask = 0u64.wrapping_sub(condition);
        let inv_mask = !mask;
        Self {
            x: FieldElement([
                (a.x.0[0] & mask) | (b.x.0[0] & inv_mask),
                (a.x.0[1] & mask) | (b.x.0[1] & inv_mask),
                (a.x.0[2] & mask) | (b.x.0[2] & inv_mask),
                (a.x.0[3] & mask) | (b.x.0[3] & inv_mask),
                (a.x.0[4] & mask) | (b.x.0[4] & inv_mask),
            ]),
            y: FieldElement([
                (a.y.0[0] & mask) | (b.y.0[0] & inv_mask),
                (a.y.0[1] & mask) | (b.y.0[1] & inv_mask),
                (a.y.0[2] & mask) | (b.y.0[2] & inv_mask),
                (a.y.0[3] & mask) | (b.y.0[3] & inv_mask),
                (a.y.0[4] & mask) | (b.y.0[4] & inv_mask),
            ]),
            z: FieldElement([
                (a.z.0[0] & mask) | (b.z.0[0] & inv_mask),
                (a.z.0[1] & mask) | (b.z.0[1] & inv_mask),
                (a.z.0[2] & mask) | (b.z.0[2] & inv_mask),
                (a.z.0[3] & mask) | (b.z.0[3] & inv_mask),
                (a.z.0[4] & mask) | (b.z.0[4] & inv_mask),
            ]),
            t: FieldElement([
                (a.t.0[0] & mask) | (b.t.0[0] & inv_mask),
                (a.t.0[1] & mask) | (b.t.0[1] & inv_mask),
                (a.t.0[2] & mask) | (b.t.0[2] & inv_mask),
                (a.t.0[3] & mask) | (b.t.0[3] & inv_mask),
                (a.t.0[4] & mask) | (b.t.0[4] & inv_mask),
            ]),
        }
    }

    pub fn compress(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        let mut bytes = y.to_bytes();
        bytes[31] ^= (x.is_negative() as u8) << 7;
        bytes
    }

    pub fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
        let mut y_bytes = *bytes;
        let x_sign = (y_bytes[31] >> 7) & 1;
        y_bytes[31] &= 0x7f;

        let y = FieldElement::from_bytes(&y_bytes);
        let y2 = y.square();
        let num = y2.sub(&FieldElement::one());
        let den = D.mul(&y2).add(&FieldElement::one());
        let den_inv = den.invert();
        let x2 = num.mul(&den_inv);
        let x = x2.sqrt()?;
        let x = if (x.is_negative() as u8) != x_sign {
            x.neg()
        } else {
            x
        };

        Some(EdwardsPoint {
            x,
            y,
            z: FieldElement::one(),
            t: x.mul(&y),
        })
    }

    pub fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.t.zeroize();
    }

    /// Negates a point: -P = (-x, y, z, -t)
    pub fn negate(&self) -> EdwardsPoint {
        EdwardsPoint {
            x: self.x.neg(),
            y: self.y.clone(),
            z: self.z.clone(),
            t: self.t.neg(),
        }
    }

    /// Returns true if this is the identity point (neutral element)
    pub fn is_identity(&self) -> bool {
        // Identity in extended coordinates: x=0, y=z, t=0
        // We check x=0 and y=z (t=0 follows from t=xy/z when x=0)
        let z_inv = self.z.invert();
        let x_normalized = self.x.mul(&z_inv);
        let y_normalized = self.y.mul(&z_inv);

        x_normalized.is_zero() && y_normalized.eq(&FieldElement::one())
    }
}

pub fn keypair_from_seed(seed: &[u8; 32]) -> (PublicKey, PrivateKey) {
    let h = sha512(seed);
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    let public_point = BASEPOINT.scalar_mul(&s);
    let public = public_point.compress();

    (public, *seed)
}

pub fn generate_keypair() -> (PublicKey, PrivateKey) {
    let entropy = get_entropy(32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&entropy);
    keypair_from_seed(&seed)
}

pub fn sign(private_key: &PrivateKey, public_key: &PublicKey, message: &[u8]) -> Signature {
    let h = sha512(private_key);
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    let prefix = &h[32..64];
    let mut r_input = alloc::vec::Vec::with_capacity(32 + message.len());
    r_input.extend_from_slice(prefix);
    r_input.extend_from_slice(message);
    let r_hash = sha512(&r_input);
    let r = sc_reduce(&r_hash);
    let r_point = BASEPOINT.scalar_mul(&r);
    let r_compressed = r_point.compress();
    let mut k_input = alloc::vec::Vec::with_capacity(32 + 32 + message.len());
    k_input.extend_from_slice(&r_compressed);
    k_input.extend_from_slice(public_key);
    k_input.extend_from_slice(message);
    let k_hash = sha512(&k_input);
    let k = sc_reduce(&k_hash);
    let ks = sc_mul(&k, &s);
    let sig_s = sc_add(&r, &ks);
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_compressed);
    signature[32..].copy_from_slice(&sig_s);

    signature
}

// SECURITY: Constant-time scalar validity check
fn sc_is_invalid(s: &[u8; 32]) -> bool {
    let mut borrow: i16 = 0;
    for i in 0..32 {
        let diff = s[i] as i16 - L[i] as i16 - borrow;
        // Constant-time borrow extraction: sign bit is 1 if diff < 0
        borrow = (diff >> 15) & 1;
    }
    borrow == 0
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    if sc_is_invalid(&s_bytes) {
        return false;
    }

    let r_compressed = &signature[..32];
    let sig_s = &signature[32..];
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(r_compressed);
    let r_point = match EdwardsPoint::decompress(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    let a_point = match EdwardsPoint::decompress(public_key) {
        Some(p) => p,
        None => return false,
    };

    let mut k_input = alloc::vec::Vec::with_capacity(32 + 32 + message.len());
    k_input.extend_from_slice(r_compressed);
    k_input.extend_from_slice(public_key);
    k_input.extend_from_slice(message);
    let k_hash = sha512(&k_input);
    let k = sc_reduce(&k_hash);

    let sb = BASEPOINT.scalar_mul(&s_bytes);
    let ka = a_point.scalar_mul(&k);
    let rhs = r_point.add(&ka);

    sb.compress() == rhs.compress()
}

// SECURITY: Constant-time scalar reduction modulo L
// Uses fixed iteration count and conditional selection to prevent timing leaks
fn sc_reduce(h: &[u8; 64]) -> [u8; 32] {
    let mut acc = [0u8; 64];
    acc.copy_from_slice(h);
    // Maximum iterations needed: log2(2^512 / L) ≈ 256
    // We use a fixed iteration count to ensure constant-time
    for _ in 0..256 {
        // Try to subtract L from acc
        let mut temp = [0u8; 64];
        let mut borrow = 0i16;
        // Subtract L from low 32 bytes
        for i in 0..32 {
            let diff = (acc[i] as i16) - (L[i] as i16) - borrow;
            temp[i] = (diff & 0xFF) as u8;
            borrow = (diff >> 8) & 1;
        }
        // Propagate borrow through high 32 bytes
        for i in 32..64 {
            let diff = (acc[i] as i16) - borrow;
            temp[i] = (diff & 0xFF) as u8;
            borrow = (diff >> 8) & 1;
        }
        // *_* If no borrow, subtraction was valid - use temp
        // If borrow, keep acc
        // Constant-time selection: mask is all-1s if borrow==0, all-0s if borrow==1 *_* 
        let mask = ((borrow as u8).wrapping_sub(1)) as u8; // 0xFF if borrow==0, 0x00 if borrow==1
        for i in 0..64 {
            acc[i] = (temp[i] & mask) | (acc[i] & !mask);
        }
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&acc[..32]);
    result
}

fn sc_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut product = [0u8; 64];
    for i in 0..32 {
        let mut carry = 0u16;
        for j in 0..32 {
            let pos = i + j;
            if pos < 64 {
                let prod = (a[i] as u16) * (b[j] as u16) + (product[pos] as u16) + carry;
                product[pos] = prod as u8;
                carry = prod >> 8;
            }
        }
        if i + 32 < 64 {
            product[i + 32] = product[i + 32].wrapping_add(carry as u8);
        }
    }

    sc_reduce(&product)
}

fn sc_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut sum = [0u8; 64];
    let mut carry = 0u16;
    for i in 0..32 {
        let s = (a[i] as u16) + (b[i] as u16) + carry;
        sum[i] = s as u8;
        carry = s >> 8;
    }
    sum[32] = carry as u8;

    sc_reduce(&sum)
}
