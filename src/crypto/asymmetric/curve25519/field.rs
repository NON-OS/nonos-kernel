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

use core::sync::atomic::{compiler_fence, Ordering};

use super::{load_u64_le, store_u64_le, SQRT_M1};

// SECURITY: No Copy trait - field elements may hold secret values during scalar multiplication
// and must be explicitly cloned and securely zeroized when dropped
#[derive(Clone)]
pub struct FieldElement(pub [u64; 5]);

impl Drop for FieldElement {
    fn drop(&mut self) {
        // SECURITY: Volatile writes ensure the compiler cannot optimize away
        // the zeroization of sensitive cryptographic data
        unsafe {
            core::ptr::write_volatile(&mut self.0[0], 0);
            core::ptr::write_volatile(&mut self.0[1], 0);
            core::ptr::write_volatile(&mut self.0[2], 0);
            core::ptr::write_volatile(&mut self.0[3], 0);
            core::ptr::write_volatile(&mut self.0[4], 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl FieldElement {
    pub const fn zero() -> Self {
        FieldElement([0, 0, 0, 0, 0])
    }

    pub const fn one() -> Self {
        FieldElement([1, 0, 0, 0, 0])
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut h = [0u64; 5];

        h[0] = load_u64_le(&bytes[0..8]) & 0x7ffffffffffff;
        h[1] = (load_u64_le(&bytes[6..14]) >> 3) & 0x7ffffffffffff;
        h[2] = (load_u64_le(&bytes[12..20]) >> 6) & 0x7ffffffffffff;
        h[3] = (load_u64_le(&bytes[19..27]) >> 1) & 0x7ffffffffffff;
        h[4] = (load_u64_le(&bytes[24..32]) >> 12) & 0x7ffffffffffff;

        FieldElement(h)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut h = self.reduce().0;

        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;

        h[0] += 19 * q;
        let c = h[0] >> 51;
        h[0] &= 0x7ffffffffffff;
        h[1] += c;
        let c = h[1] >> 51;
        h[1] &= 0x7ffffffffffff;
        h[2] += c;
        let c = h[2] >> 51;
        h[2] &= 0x7ffffffffffff;
        h[3] += c;
        let c = h[3] >> 51;
        h[3] &= 0x7ffffffffffff;
        h[4] += c;
        h[4] &= 0x7ffffffffffff;

        let mut bytes = [0u8; 32];
        store_u64_le(&mut bytes[0..8], h[0] | (h[1] << 51));
        store_u64_le(&mut bytes[8..16], (h[1] >> 13) | (h[2] << 38));
        store_u64_le(&mut bytes[16..24], (h[2] >> 26) | (h[3] << 25));
        store_u64_le(&mut bytes[24..32], (h[3] >> 39) | (h[4] << 12));

        bytes
    }

    pub fn add(&self, other: &FieldElement) -> FieldElement {
        FieldElement([
            self.0[0] + other.0[0],
            self.0[1] + other.0[1],
            self.0[2] + other.0[2],
            self.0[3] + other.0[3],
            self.0[4] + other.0[4],
        ])
        .reduce()
    }

    pub fn sub(&self, other: &FieldElement) -> FieldElement {
        FieldElement([
            (self.0[0] + 36028797018963664u64).wrapping_sub(other.0[0]),
            (self.0[1] + 36028797018963952u64).wrapping_sub(other.0[1]),
            (self.0[2] + 36028797018963952u64).wrapping_sub(other.0[2]),
            (self.0[3] + 36028797018963952u64).wrapping_sub(other.0[3]),
            (self.0[4] + 36028797018963952u64).wrapping_sub(other.0[4]),
        ])
        .reduce()
    }

    pub fn mul(&self, other: &FieldElement) -> FieldElement {
        let a = &self.0;
        let b = &other.0;

        let m0 = (a[0] as u128) * (b[0] as u128);
        let m1 = (a[0] as u128) * (b[1] as u128) + (a[1] as u128) * (b[0] as u128);
        let m2 = (a[0] as u128) * (b[2] as u128)
            + (a[1] as u128) * (b[1] as u128)
            + (a[2] as u128) * (b[0] as u128);
        let m3 = (a[0] as u128) * (b[3] as u128)
            + (a[1] as u128) * (b[2] as u128)
            + (a[2] as u128) * (b[1] as u128)
            + (a[3] as u128) * (b[0] as u128);
        let m4 = (a[0] as u128) * (b[4] as u128)
            + (a[1] as u128) * (b[3] as u128)
            + (a[2] as u128) * (b[2] as u128)
            + (a[3] as u128) * (b[1] as u128)
            + (a[4] as u128) * (b[0] as u128);
        let m5 = (a[1] as u128) * (b[4] as u128)
            + (a[2] as u128) * (b[3] as u128)
            + (a[3] as u128) * (b[2] as u128)
            + (a[4] as u128) * (b[1] as u128);
        let m6 = (a[2] as u128) * (b[4] as u128)
            + (a[3] as u128) * (b[3] as u128)
            + (a[4] as u128) * (b[2] as u128);
        let m7 = (a[3] as u128) * (b[4] as u128) + (a[4] as u128) * (b[3] as u128);
        let m8 = (a[4] as u128) * (b[4] as u128);

        let r0 = m0 + 19 * m5;
        let r1 = m1 + 19 * m6;
        let r2 = m2 + 19 * m7;
        let r3 = m3 + 19 * m8;
        let r4 = m4;
        let c = r0 >> 51;
        let h0 = (r0 as u64) & 0x7ffffffffffff;
        let r1 = r1 + c;
        let c = r1 >> 51;
        let h1 = (r1 as u64) & 0x7ffffffffffff;
        let r2 = r2 + c;
        let c = r2 >> 51;
        let h2 = (r2 as u64) & 0x7ffffffffffff;
        let r3 = r3 + c;
        let c = r3 >> 51;
        let h3 = (r3 as u64) & 0x7ffffffffffff;
        let r4 = r4 + c;
        let c = r4 >> 51;
        let h4 = (r4 as u64) & 0x7ffffffffffff;

        let h0 = h0 + (19 * c) as u64;

        FieldElement([h0, h1, h2, h3, h4]).reduce()
    }

    #[inline]
    pub fn square(&self) -> FieldElement {
        self.mul(self)
    }

    pub fn mul121666(&self) -> FieldElement {
        let mut h = [0u64; 5];
        let mut c = 0u128;

        for i in 0..5 {
            c += (self.0[i] as u128) * 121666;
            h[i] = (c as u64) & 0x7ffffffffffff;
            c >>= 51;
        }
        h[0] += (19 * c) as u64;

        FieldElement(h).reduce()
    }

    fn reduce(&self) -> FieldElement {
        const LOW_51_BIT_MASK: u64 = (1u64 << 51) - 1;

        let mut limbs = self.0;

        let c0 = limbs[0] >> 51;
        let c1 = limbs[1] >> 51;
        let c2 = limbs[2] >> 51;
        let c3 = limbs[3] >> 51;
        let c4 = limbs[4] >> 51;

        limbs[0] &= LOW_51_BIT_MASK;
        limbs[1] &= LOW_51_BIT_MASK;
        limbs[2] &= LOW_51_BIT_MASK;
        limbs[3] &= LOW_51_BIT_MASK;
        limbs[4] &= LOW_51_BIT_MASK;

        limbs[0] += c4 * 19;
        limbs[1] += c0;
        limbs[2] += c1;
        limbs[3] += c2;
        limbs[4] += c3;

        let c0 = limbs[0] >> 51;
        let c1 = limbs[1] >> 51;
        let c2 = limbs[2] >> 51;
        let c3 = limbs[3] >> 51;
        let c4 = limbs[4] >> 51;

        limbs[0] &= LOW_51_BIT_MASK;
        limbs[1] &= LOW_51_BIT_MASK;
        limbs[2] &= LOW_51_BIT_MASK;
        limbs[3] &= LOW_51_BIT_MASK;
        limbs[4] &= LOW_51_BIT_MASK;

        limbs[0] += c4 * 19;
        limbs[1] += c0;
        limbs[2] += c1;
        limbs[3] += c2;
        limbs[4] += c3;

        FieldElement(limbs)
    }

    pub fn invert(&self) -> FieldElement {
        let z1 = *self;
        let z2 = z1.square();
        let z4 = z2.square();
        let z8 = z4.square();
        let z9 = z8.mul(&z1);
        let z11 = z9.mul(&z2);
        let z22 = z11.square();
        let z_5_0 = z22.mul(&z9);

        let mut t = z_5_0.square();
        for _ in 1..5 {
            t = t.square();
        }
        let z_10_0 = t.mul(&z_5_0);

        let mut t = z_10_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_20_0 = t.mul(&z_10_0);

        let mut t = z_20_0.square();
        for _ in 1..20 {
            t = t.square();
        }
        let z_40_0 = t.mul(&z_20_0);

        let mut t = z_40_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_50_0 = t.mul(&z_10_0);

        let mut t = z_50_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_100_0 = t.mul(&z_50_0);

        let mut t = z_100_0.square();
        for _ in 1..100 {
            t = t.square();
        }
        let z_200_0 = t.mul(&z_100_0);

        let mut t = z_200_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_250_0 = t.mul(&z_50_0);

        let mut t = z_250_0.square();
        for _ in 1..5 {
            t = t.square();
        }
        t.mul(&z11)
    }

    pub fn sqrt(&self) -> Option<FieldElement> {
        let z1 = *self;
        let z2 = z1.square();
        let z4 = z2.square();
        let z8 = z4.square();
        let z9 = z8.mul(&z1);
        let z11 = z9.mul(&z2);
        let z22 = z11.square();
        let z_5_0 = z22.mul(&z9);

        let mut t = z_5_0.square();
        for _ in 1..5 {
            t = t.square();
        }
        let z_10_0 = t.mul(&z_5_0);

        let mut t = z_10_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_20_0 = t.mul(&z_10_0);

        let mut t = z_20_0.square();
        for _ in 1..20 {
            t = t.square();
        }
        let z_40_0 = t.mul(&z_20_0);

        let mut t = z_40_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_50_0 = t.mul(&z_10_0);

        let mut t = z_50_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_100_0 = t.mul(&z_50_0);

        let mut t = z_100_0.square();
        for _ in 1..100 {
            t = t.square();
        }
        let z_200_0 = t.mul(&z_100_0);

        let mut t = z_200_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_250_0 = t.mul(&z_50_0);
        let mut t = z_250_0.square();
        t = t.square();
        let beta = t.mul(&z2);

        let beta_sq = beta.square();
        if beta_sq.ct_eq(self) {
            return Some(beta);
        }

        let sqrt_m1 = SQRT_M1;
        let beta_i = beta.mul(&sqrt_m1);
        let beta_i_sq = beta_i.square();
        if beta_i_sq.ct_eq(self) {
            return Some(beta_i);
        }

        None
    }

    pub fn ct_eq(&self, other: &FieldElement) -> bool {
        let a = self.to_bytes();
        let b = other.to_bytes();
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }

    pub fn is_negative(&self) -> bool {
        let bytes = self.to_bytes();
        (bytes[0] & 1) == 1
    }

    pub fn neg(&self) -> FieldElement {
        FieldElement::zero().sub(self)
    }

    pub fn conditional_swap(swap: u8, a: &mut FieldElement, b: &mut FieldElement) {
        let mask = (swap as u64).wrapping_neg();
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    pub fn zeroize(&mut self) {
        for limb in &mut self.0 {
            // SAFETY: We use volatile write to prevent the compiler from optimizing
            // away this zeroing operation. This is critical for security to ensure
            // sensitive cryptographic material is actually cleared from memory.
            unsafe {
                core::ptr::write_volatile(limb, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }

    pub fn is_zero(&self) -> bool {
        let bytes = self.to_bytes();
        let mut acc = 0u8;
        for b in &bytes {
            acc |= *b;
        }
        acc == 0
    }

    pub fn eq(&self, other: &FieldElement) -> bool {
        let a = self.to_bytes();
        let b = other.to_bytes();
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }
}
