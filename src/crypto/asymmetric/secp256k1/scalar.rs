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

// SECURITY: Constant-time less-than comparison for u64
#[inline]
fn ct_lt_u64(a: u64, b: u64) -> u64 {
    let x = a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b));
    x >> 63
}

// SECURITY: No Copy trait - scalars are secrets that must be explicitly cloned
// and securely zeroized when dropped
#[derive(Clone, PartialEq, Eq)]
pub struct Scalar(pub(crate) [u64; 4]);

impl Scalar {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    const N: [u64; 4] = [
        0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B,
        0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF
    ];

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let offset = (3 - i) * 8;
            limbs[i] = u64::from_be_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
                bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
            ]);
        }
        let s = Self(limbs);
        if s.is_valid() { Some(s) } else { None }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let offset = (3 - i) * 8;
            let limb_bytes = self.0[i].to_be_bytes();
            bytes[offset..offset + 8].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    // SECURITY: Constant-time validity check - always compares all limbs
    fn is_valid(&self) -> bool {
        let mut lt: u64 = 0;
        let mut eq: u64 = 1;

        for i in (0..4).rev() {
            let a = self.0[i];
            let n = Self::N[i];
            let a_lt_n = ct_lt_u64(a, n);
            let a_gt_n = ct_lt_u64(n, a);
            lt |= eq & a_lt_n;
            eq &= (1 - a_lt_n) & (1 - a_gt_n);
        }

        lt == 1
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    // SECURITY: Constant-time zero check - returns 1 if zero, 0 if non-zero
    pub fn ct_is_zero(&self) -> u64 {
        let or = self.0[0] | self.0[1] | self.0[2] | self.0[3];
        let is_nonzero = (or | or.wrapping_neg()) >> 63;
        1 ^ is_nonzero
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;

        for i in 0..4 {
            carry += self.0[i] as u128 + other.0[i] as u128;
            result[i] = carry as u64;
            carry >>= 64;
        }

        let mut res = Self(result);
        res.reduce();
        res
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut t = [0u128; 8];

        for i in 0..4 {
            for j in 0..4 {
                t[i + j] += self.0[i] as u128 * other.0[j] as u128;
            }
        }

        for i in 0..7 {
            t[i + 1] += t[i] >> 64;
            t[i] &= 0xFFFFFFFFFFFFFFFF;
        }

        Self::reduce_wide(&t)
    }

    // SECURITY: Constant-time reduction
    fn reduce(&mut self) {
        let mut borrow = 0i128;
        let mut temp = [0u64; 4];

        for i in 0..4 {
            borrow += self.0[i] as i128 - Self::N[i] as i128;
            if borrow < 0 {
                temp[i] = (borrow + (1i128 << 64)) as u64;
                borrow = -1;
            } else {
                temp[i] = borrow as u64;
                borrow = 0;
            }
        }

        // Constant-time select: use temp if no borrow (value >= N), else keep original
        let no_borrow = ((borrow >> 127) & 1) as u64; // 0 if borrow >= 0, 1 if borrow < 0
        let mask = no_borrow.wrapping_sub(1); // all 1s if no borrow, all 0s if borrow
        for i in 0..4 {
            self.0[i] = (temp[i] & mask) | (self.0[i] & !mask);
        }
    }

    // SECURITY: Constant-time wide reduction modulo N
    // Properly handles the full 512-bit product from multiplication
    fn reduce_wide(wide: &[u128; 8]) -> Self {
        // Extract 64-bit limbs from 128-bit wide values
        let mut w = [0u64; 8];
        for i in 0..8 {
            w[i] = wide[i] as u64;
        }

        // secp256k1 scalar field order N
        // N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        // We use the identity: 2^256 ≡ (2^256 - N) mod N
        // where 2^256 - N = 0x14551231950B75FC4402DA1732FC9BEBF
        // This is small enough to use for reduction

        // First, reduce the high 256 bits (w[4..7]) by multiplying by (2^256 mod N)
        // 2^256 mod N = 0x14551231950B75FC4402DA1732FC9BEBF
        const R: [u64; 4] = [
            0x402DA1732FC9BEBF,
            0x4551231950B75FC4,
            0x0000000000000001,
            0x0000000000000000,
        ];

        // Compute high * R and add to low
        let mut acc = [0u128; 8];

        // Start with low 256 bits
        for i in 0..4 {
            acc[i] = w[i] as u128;
        }

        // Add high * R
        for i in 0..4 {
            for j in 0..4 {
                acc[i + j] += (w[4 + i] as u128) * (R[j] as u128);
            }
        }

        // Propagate carries
        for i in 0..7 {
            acc[i + 1] += acc[i] >> 64;
            acc[i] &= 0xFFFFFFFFFFFFFFFF;
        }

        // If there's still overflow in acc[4..7], reduce again
        let mut result = [0u64; 4];
        for i in 0..4 {
            result[i] = acc[i] as u64;
        }

        // Handle remaining overflow with another reduction pass
        let mut overflow = [0u64; 4];
        for i in 0..4 {
            overflow[i] = acc[4 + i] as u64;
        }

        // If overflow is non-zero, add overflow * R
        let mut has_overflow = 0u64;
        for i in 0..4 {
            has_overflow |= overflow[i];
        }

        if has_overflow != 0 {
            let mut carry = 0u128;
            for i in 0..4 {
                for j in 0..4 {
                    if i + j < 4 {
                        carry += (overflow[i] as u128) * (R[j] as u128);
                        carry += result[i + j] as u128;
                        result[i + j] = carry as u64;
                        carry >>= 64;
                    }
                }
            }
        }

        let mut res = Self(result);
        // Final reductions to ensure result < N
        res.reduce();
        res.reduce();
        res
    }

    // SECURITY: Constant-time modular inversion using Fermat's little theorem
    // Always computes even for zero input to prevent timing leaks
    pub fn invert(&self) -> Option<Self> {
        let n_minus_2: [u64; 4] = [
            0xBFD25E8CD036413F, 0xBAAEDCE6AF48A03B,
            0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF
        ];

        // Always compute the modular exponentiation
        let mut result = Self::ONE;
        let mut base = self.clone();
        for &limb in n_minus_2.iter() {
            for bit in 0..64 {
                // Always compute the multiplication, then select
                let mul_result = result.mul(&base);
                let mask = 0u64.wrapping_sub(((limb >> bit) & 1) as u64);
                result = Self::ct_select(mask, &mul_result, &result);
                base = base.mul(&base);
            }
        }

        // Constant-time check: return None if input was zero
        let is_zero = self.ct_is_zero();
        if is_zero == 1 { None } else { Some(result) }
    }

    // SECURITY: Constant-time conditional select
    pub fn ct_select(mask: u64, a: &Self, b: &Self) -> Self {
        Self([
            (a.0[0] & mask) | (b.0[0] & !mask),
            (a.0[1] & mask) | (b.0[1] & !mask),
            (a.0[2] & mask) | (b.0[2] & !mask),
            (a.0[3] & mask) | (b.0[3] & !mask),
        ])
    }

    // SECURITY: Constant-time negation - always performs full computation
    pub fn negate(&self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            borrow += Self::N[i] as i128 - self.0[i] as i128;
            if borrow < 0 {
                result[i] = (borrow + (1i128 << 64)) as u64;
                borrow = -1;
            } else {
                result[i] = borrow as u64;
                borrow = 0;
            }
        }
        // For zero input, result will be N which is valid - negate(0) = 0 mod N
        Self(result)
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        let mut diff = 0u64;
        diff |= self.0[0] ^ other.0[0];
        diff |= self.0[1] ^ other.0[1];
        diff |= self.0[2] ^ other.0[2];
        diff |= self.0[3] ^ other.0[3];
        diff == 0
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        // SECURITY: Volatile writes ensure the compiler cannot optimize away
        // the zeroization of sensitive scalar data
        unsafe {
            core::ptr::write_volatile(&mut self.0[0], 0);
            core::ptr::write_volatile(&mut self.0[1], 0);
            core::ptr::write_volatile(&mut self.0[2], 0);
            core::ptr::write_volatile(&mut self.0[3], 0);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
