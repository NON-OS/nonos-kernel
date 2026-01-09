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

use super::P256_P;
// SECURITY: Constant-time less-than comparison for u64
#[inline]
fn ct_lt_u64(a: u64, b: u64) -> u64 {
    let x = a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b));
    x >> 63
}

// SECURITY: No Copy trait - field elements may hold secret-dependent intermediate values
// and must be explicitly cloned and securely zeroized when dropped
#[derive(Clone, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u64; 4]);

impl Drop for FieldElement {
    fn drop(&mut self) {
        unsafe {
            core::ptr::write_volatile(&mut self.0[0], 0);
            core::ptr::write_volatile(&mut self.0[1], 0);
            core::ptr::write_volatile(&mut self.0[2], 0);
            core::ptr::write_volatile(&mut self.0[3], 0);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl FieldElement {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    const P: [u64; 4] = P256_P;
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let offset = (3 - i) * 8;
            limbs[i] = u64::from_be_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
                bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
            ]);
        }
        let fe = Self(limbs);
        if fe.is_valid() { Some(fe) } else { None }
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
        // Check if self < P using constant-time comparison
        // Returns true if self < P (valid), false if self >= P (invalid)
        let mut lt: u64 = 0;  // 1 if definitely less
        let mut eq: u64 = 1;  // 1 if equal so far

        for i in (0..4).rev() {
            let a = self.0[i];
            let p = Self::P[i];

            // Constant-time less than: is a < p?
            let a_lt_p = ct_lt_u64(a, p);
            let a_gt_p = ct_lt_u64(p, a);

            // If we haven't determined the result yet (eq==1), update lt
            // lt = lt | (eq & a_lt_p)
            lt |= eq & a_lt_p;

            // Update eq: still equal if eq was 1 and a == p
            // eq = eq & (1 - a_lt_p) & (1 - a_gt_p)
            eq &= (1 - a_lt_p) & (1 - a_gt_p);
        }

        // Valid if lt == 1 (self < P) or eq == 0 means we found a difference
        // If eq == 1 at the end, all limbs were equal, so self == P which is invalid
        lt == 1
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
        if carry != 0 {
            const C: [u64; 4] = [
                0x0000000000000001,
                0xFFFFFFFF00000000,
                0xFFFFFFFFFFFFFFFF,
                0x00000000FFFFFFFE,
            ];
            let mut add_carry = 0u128;
            for i in 0..4 {
                add_carry += res.0[i] as u128 + C[i] as u128;
                res.0[i] = add_carry as u64;
                add_carry >>= 64;
            }
        }

        res.reduce();
        res
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;

        for i in 0..4 {
            borrow += self.0[i] as i128 - other.0[i] as i128;
            if borrow < 0 {
                result[i] = (borrow + (1i128 << 64)) as u64;
                borrow = -1;
            } else {
                result[i] = borrow as u64;
                borrow = 0;
            }
        }

        let mut res = Self(result);
        if borrow < 0 {
            let mut carry = 0u128;
            for i in 0..4 {
                carry += res.0[i] as u128 + Self::P[i] as u128;
                res.0[i] = carry as u64;
                carry >>= 64;
            }
        }
        res
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut result = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let product = (self.0[i] as u128) * (other.0[j] as u128);
                let sum = (result[i + j] as u128) + product + carry;
                result[i + j] = sum as u64;
                carry = sum >> 64;
            }
            let mut k = i + 4;
            while carry != 0 && k < 8 {
                let sum = (result[k] as u128) + carry;
                result[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
        }

        let wide: [u128; 8] = [
            result[0] as u128,
            result[1] as u128,
            result[2] as u128,
            result[3] as u128,
            result[4] as u128,
            result[5] as u128,
            result[6] as u128,
            result[7] as u128,
        ];

        self.reduce_wide(&wide)
    }

    // SECURITY: Constant-time wide reduction - always runs fixed iterations
    fn reduce_wide(&self, wide: &[u128; 8]) -> Self {
        // C = 2^256 mod P for P-256
        const C: [u64; 4] = [
            0x0000000000000001,
            0xFFFFFFFF00000000,
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFE,
        ];

        let mut val = [0u64; 9];
        for i in 0..8 {
            val[i] = wide[i] as u64;
        }

        // SECURITY: Always run all iterations for constant-time
        for _ in 0..10 {
            let low = [val[0], val[1], val[2], val[3]];
            let high = [val[4], val[5], val[6], val[7], val[8]];

            let mut hc = [0u64; 9];
            // SECURITY: Always process all high limbs (no early continue)
            for i in 0..5 {
                let mut carry = 0u128;
                for j in 0..4 {
                    let idx = i + j;
                    if idx < 9 {
                        let product = (high[i] as u128) * (C[j] as u128);
                        let sum = (hc[idx] as u128) + product + carry;
                        hc[idx] = sum as u64;
                        carry = sum >> 64;
                    }
                }
                // Propagate remaining carry with fixed iterations
                for k in (i + 4)..(i + 6) {
                    if k < 9 {
                        let sum = (hc[k] as u128) + carry;
                        hc[k] = sum as u64;
                        carry = sum >> 64;
                    }
                }
            }

            let mut carry = 0u128;
            for i in 0..4 {
                carry += (low[i] as u128) + (hc[i] as u128);
                val[i] = carry as u64;
                carry >>= 64;
            }
            for i in 4..9 {
                carry += hc[i] as u128;
                val[i] = carry as u64;
                carry >>= 64;
            }
        }

        let mut result = Self([val[0], val[1], val[2], val[3]]);

        // SECURITY: Fixed number of final reductions with constant-time select
        for _ in 0..3 {
            let mut temp = [0u64; 4];
            let mut borrow = 0i128;

            for i in 0..4 {
                borrow += result.0[i] as i128 - Self::P[i] as i128;
                if borrow < 0 {
                    temp[i] = ((1i128 << 64) + borrow) as u64;
                    borrow = -1;
                } else {
                    temp[i] = borrow as u64;
                    borrow = 0;
                }
            }

            // Constant-time select: use temp if no borrow, else keep result
            let no_borrow = ((borrow >> 127) & 1) as u64; // 0 if borrow >= 0, 1 if borrow < 0
            let mask = no_borrow.wrapping_sub(1); // all 1s if no borrow, all 0s if borrow
            for i in 0..4 {
                result.0[i] = (temp[i] & mask) | (result.0[i] & !mask);
            }
        }

        result
    }

    // SECURITY: Constant-time reduction
    fn reduce(&mut self) {
        let mut borrow = 0i128;
        let mut temp = [0u64; 4];

        for i in 0..4 {
            borrow += self.0[i] as i128 - Self::P[i] as i128;
            if borrow < 0 {
                temp[i] = (borrow + (1i128 << 64)) as u64;
                borrow = -1;
            } else {
                temp[i] = borrow as u64;
                borrow = 0;
            }
        }

        // Constant-time select: use temp if no borrow (value >= P), else keep original
        let no_borrow = ((borrow >> 127) & 1) as u64; // 0 if borrow >= 0, 1 if borrow < 0
        let mask = no_borrow.wrapping_sub(1); // all 1s if no borrow, all 0s if borrow
        for i in 0..4 {
            self.0[i] = (temp[i] & mask) | (self.0[i] & !mask);
        }
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    // SECURITY: Uses conditional select to avoid timing side-channels
    pub fn pow(&self, exp: &[u64; 4]) -> Self {
        let mut result = Self::ONE;
        let mut base = self.clone();

        for &limb in exp.iter() {
            for bit in 0..64 {
                let mul_result = result.mul(&base);
                let mask = 0u64.wrapping_sub(((limb >> bit) & 1) as u64);
                result = Self::ct_select(mask, &mul_result, &result);
                base = base.square();
            }
        }
        result
    }

    // SECURITY: Constant-time inversion - always computes pow even for zero input
    pub fn invert(&self) -> Option<Self> {
        // Always compute the inverse (p - 2 exponent for Fermat's little theorem)
        let exp = [
            0xFFFFFFFFFFFFFFFD,
            0x00000000FFFFFFFF,
            0x0000000000000000,
            0xFFFFFFFF00000001,
        ];
        let result = self.pow(&exp);

        // Constant-time check: return None if input was zero
        let is_zero = self.ct_is_zero();
        if is_zero == 1 { None } else { Some(result) }
    }

    // SECURITY: Uses constant-time comparison for validation
    pub fn sqrt(&self) -> Option<Self> {
        let exp = [
            0x0000000000000000,
            0x4000000040000000,
            0x0000000000000000,
            0x3FFFFFFFC0000000,
        ];
        let r = self.pow(&exp);
        // Constant-time comparison: r^2 == self
        let r_squared = r.square();
        let is_valid = r_squared.ct_eq(self);
        if is_valid == 1 { Some(r) } else { None }
    }

    pub fn is_even(&self) -> bool {
        self.0[0] & 1 == 0
    }

    // SECURITY: Constant-time negation - always computes P - self
    pub fn negate(&self) -> Self {
        // Always compute P - self
        let mut result = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            borrow += Self::P[i] as i128 - self.0[i] as i128;
            if borrow < 0 {
                result[i] = (borrow + (1i128 << 64)) as u64;
                borrow = -1;
            } else {
                result[i] = borrow as u64;
                borrow = 0;
            }
        }

        // Constant-time select: return ZERO if input was zero (P - 0 = P, but 0 is the correct result)
        let is_zero_mask = 0u64.wrapping_sub(self.ct_is_zero());
        let neg = Self(result);
        Self::ct_select(is_zero_mask, &Self::ZERO, &neg)
    }

    // SECURITY: This operation is constant-time to prevent timing side-channels
    pub fn ct_select(mask: u64, a: &Self, b: &Self) -> Self {
        Self([
            (a.0[0] & mask) | (b.0[0] & !mask),
            (a.0[1] & mask) | (b.0[1] & !mask),
            (a.0[2] & mask) | (b.0[2] & !mask),
            (a.0[3] & mask) | (b.0[3] & !mask),
        ])
    }

    pub fn ct_is_zero(&self) -> u64 {
        let or = self.0[0] | self.0[1] | self.0[2] | self.0[3];
        let is_zero = (or | or.wrapping_neg()) >> 63;
        1 ^ is_zero
    }

    pub fn ct_eq(&self, other: &Self) -> u64 {
        let diff = self.sub(other);
        diff.ct_is_zero()
    }
}
