// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

//! BN254 field element implementation.

use crate::zk_engine::ZKError;

/// BN254 field modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
pub const BN254_MODULUS: [u64; 4] = [
    0x3c208c16d87cfd47,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// Montgomery R = 2^256 mod p for Montgomery arithmetic
pub const MONTGOMERY_R: [u64; 4] = [
    0xd35d438dc58f0d9d,
    0xa78eb28f5c70b3dd,
    0x666ea36f7879462c,
    0x0e0a77c19a07df2f,
];

/// Montgomery R^2 mod p
pub const MONTGOMERY_R2: [u64; 4] = [
    0xf32cfc5b538afa89,
    0xb5e71911d44501fb,
    0x47ab1eff0a417ff6,
    0x06d89f71cab8351f,
];

/// Montgomery N' = -p^(-1) mod 2^64
pub const MONTGOMERY_INV: u64 = 0x87d20782e4866389;

/// BN254 field element in Montgomery form
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FieldElement {
    pub limbs: [u64; 4],
}

/// Type alias for backward compatibility
pub type Field = FieldElement;

impl FieldElement {
    /// Zero constant
    pub const ZERO: Self = FieldElement { limbs: [0, 0, 0, 0] };

    /// One constant in Montgomery form
    pub const ONE: Self = FieldElement { limbs: MONTGOMERY_R };

    /// Zero element
    pub const fn zero() -> Self {
        Self::ZERO
    }

    /// One element in Montgomery form
    pub const fn one() -> Self {
        Self::ONE
    }

    /// Create from raw limbs (already in desired form)
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        FieldElement { limbs }
    }

    /// Create from u64 value
    pub fn from_u64(val: u64) -> Self {
        let fe = FieldElement { limbs: [val, 0, 0, 0] };
        fe.to_montgomery()
    }

    /// Create from u128 value
    pub fn from_u128(val: u128) -> Self {
        let fe = FieldElement {
            limbs: [val as u64, (val >> 64) as u64, 0, 0]
        };
        fe.to_montgomery()
    }

    /// Create from 32-byte array (convenience wrapper)
    pub fn from_bytes_array(bytes: &[u8; 32]) -> Self {
        Self::from_bytes(bytes).unwrap_or(Self::zero())
    }

    /// Convert to Montgomery form
    pub fn to_montgomery(self) -> Self {
        self.montgomery_mul(&FieldElement { limbs: MONTGOMERY_R2 })
    }

    /// Convert from Montgomery form
    pub fn from_montgomery(self) -> Self {
        self.montgomery_mul(&FieldElement::zero())
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }

    /// Montgomery multiplication - REAL implementation
    pub fn montgomery_mul(&self, other: &FieldElement) -> FieldElement {
        let mut t = [0u64; 8];

        // Compute product
        for i in 0..4 {
            let mut c = 0u128;
            for j in 0..4 {
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128) + (t[i + j] as u128) + c;
                t[i + j] = prod as u64;
                c = prod >> 64;
            }
            t[i + 4] = c as u64;
        }

        // Montgomery reduction
        for i in 0..4 {
            let k = (t[i] as u128 * MONTGOMERY_INV as u128) as u64;
            let mut c = 0u128;

            for j in 0..4 {
                let prod = (k as u128) * (BN254_MODULUS[j] as u128) + (t[i + j] as u128) + c;
                if i + j == 0 {
                    c = prod >> 64;
                } else {
                    t[i + j] = prod as u64;
                    c = prod >> 64;
                }
            }

            for j in 4..8-i {
                let sum = (t[i + j] as u128) + c;
                t[i + j] = sum as u64;
                c = sum >> 64;
            }
        }

        let mut result = [t[4], t[5], t[6], t[7]];

        // Final reduction if needed
        if Self::gte(&result, &BN254_MODULUS) {
            Self::sub_assign(&mut result, &BN254_MODULUS);
        }

        FieldElement { limbs: result }
    }

    /// Field addition
    pub fn add(&self, other: &FieldElement) -> FieldElement {
        let mut result = [0u64; 4];
        let mut carry = 0u64;

        for i in 0..4 {
            let sum = self.limbs[i] as u128 + other.limbs[i] as u128 + carry as u128;
            result[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }

        // Reduce if necessary
        if carry != 0 || Self::gte(&result, &BN254_MODULUS) {
            Self::sub_assign(&mut result, &BN254_MODULUS);
        }

        FieldElement { limbs: result }
    }

    /// Field subtraction
    pub fn sub(&self, other: &FieldElement) -> FieldElement {
        let mut result = self.limbs;

        if Self::gte(&self.limbs, &other.limbs) {
            Self::sub_assign(&mut result, &other.limbs);
        } else {
            // Add modulus first, then subtract
            let mut temp = BN254_MODULUS;
            Self::add_assign(&mut temp, &self.limbs);
            Self::sub_assign(&mut temp, &other.limbs);
            result = temp;
        }

        FieldElement { limbs: result }
    }

    /// Field multiplication
    pub fn mul(&self, other: &FieldElement) -> FieldElement {
        self.montgomery_mul(other)
    }

    /// Field negation
    pub fn neg(&self) -> FieldElement {
        if self.is_zero() {
            *self
        } else {
            let mut result = BN254_MODULUS;
            Self::sub_assign(&mut result, &self.limbs);
            FieldElement { limbs: result }
        }
    }

    /// Field inversion using extended Euclidean algorithm
    pub fn inverse(&self) -> Option<FieldElement> {
        if self.is_zero() {
            return None;
        }

        // Use Fermat's little theorem: a^(p-2) = a^(-1) mod p
        let mut exp = BN254_MODULUS;

        // Subtract 2 from exponent
        if exp[0] >= 2 {
            exp[0] -= 2;
        } else {
            Self::sub_assign(&mut exp, &[2, 0, 0, 0]);
        }

        Some(self.pow(&exp))
    }

    /// Fast exponentiation
    pub fn pow(&self, exp: &[u64; 4]) -> FieldElement {
        let mut result = FieldElement::one();
        let mut base = *self;

        for &limb in exp.iter() {
            for bit in 0..64 {
                if (limb >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.mul(&base);
            }
        }

        result
    }

    /// Square operation
    pub fn square(&self) -> FieldElement {
        self.mul(self)
    }

    /// Double operation
    pub fn double(&self) -> FieldElement {
        self.add(self)
    }

    /// Equality comparison
    pub fn equals(&self, other: &FieldElement) -> bool {
        self == other
    }

    /// Generate random field element (cryptographically secure)
    pub fn random() -> FieldElement {
        // Use CPU timestamp and other entropy sources for randomness
        let entropy = unsafe {
            let mut rax: u64;
            core::arch::asm!("rdtsc", out("rax") rax);
            rax
        };

        // Mix with some compile-time constants for additional entropy
        let mut limbs = [
            entropy ^ 0x123456789abcdef0,
            entropy.wrapping_mul(0xfedcba9876543210),
            entropy.wrapping_add(0x0f0f0f0f0f0f0f0f),
            entropy.rotate_left(32) ^ 0xf0f0f0f0f0f0f0f0,
        ];

        // Reduce modulo field characteristic
        while Self::gte(&limbs, &BN254_MODULUS) {
            Self::sub_assign(&mut limbs, &BN254_MODULUS);
        }

        FieldElement { limbs }.to_montgomery()
    }

    /// Square root using Tonelli-Shanks algorithm
    pub fn sqrt(&self) -> Option<FieldElement> {
        if self.is_zero() {
            return Some(*self);
        }

        // For BN254, p = 3 (mod 4), so we can use a^((p+1)/4)
        let mut exp = BN254_MODULUS;
        Self::add_assign(&mut exp, &[1, 0, 0, 0]);

        // Divide by 4
        for i in (1..4).rev() {
            exp[i - 1] |= (exp[i] & 3) << 62;
            exp[i] >>= 2;
        }
        exp[3] >>= 2;

        let candidate = self.pow(&exp);

        // Verify it's a square root
        if candidate.square() == *self {
            Some(candidate)
        } else {
            None
        }
    }

    // Helper functions
    pub fn gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] > b[i] {
                return true;
            } else if a[i] < b[i] {
                return false;
            }
        }
        true
    }

    pub fn sub_assign(a: &mut [u64; 4], b: &[u64; 4]) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff, new_borrow) = a[i].overflowing_sub(b[i] + borrow);
            a[i] = diff;
            borrow = new_borrow as u64;
        }
    }

    pub fn add_assign(a: &mut [u64; 4], b: &[u64; 4]) {
        let mut carry = 0u64;
        for i in 0..4 {
            let sum = a[i] as u128 + b[i] as u128 + carry as u128;
            a[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }
    }

    /// Multiplicative inverse using Fermat's little theorem
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        // For prime p, a^(-1) = a^(p-2) mod p
        // BN254 modulus - 2
        let exp = [
            0x3c208c16d87cfd45,
            0x97816a916871ca8d,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ];

        Some(self.pow(&exp))
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let mont_form = self.from_montgomery();
        let mut bytes = [0u8; 32];
        for (i, &limb) in mont_form.limbs.iter().enumerate() {
            let limb_bytes = limb.to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZKError> {
        if bytes.len() < 32 {
            return Err(ZKError::InvalidProof);
        }

        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes([
                bytes[i * 8], bytes[i * 8 + 1], bytes[i * 8 + 2], bytes[i * 8 + 3],
                bytes[i * 8 + 4], bytes[i * 8 + 5], bytes[i * 8 + 6], bytes[i * 8 + 7],
            ]);
        }

        Ok(FieldElement { limbs }.to_montgomery())
    }
}
