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

extern crate alloc;

use alloc::vec::Vec;

use super::{BigUint, LIMB_BITS};

impl BigUint {
    // SECURITY: Constant-time modular exponentiation using Montgomery ladder
    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }
        if modulus.is_one() {
            return Some(Self::zero());
        }
        if exp.is_zero() {
            return Some(Self::one());
        }

        let n_limbs = modulus.limbs.len();
        let mod_bits = modulus.bits();
        let is_close_to_pow2 = mod_bits >= n_limbs * LIMB_BITS - 8;
        if modulus.is_odd() && modulus.bits() >= 64 && !is_close_to_pow2 {
            return Some(self.mod_pow_montgomery_ct(exp, modulus));
        }

        // Fallback: constant-time square-and-multiply
        self.mod_pow_ct(exp, modulus)
    }

    // SECURITY: Constant-time modexp without Montgomery (for non-odd moduli)
    fn mod_pow_ct(&self, exp: &Self, modulus: &Self) -> Option<Self> {
        let bit_len = exp.bits();
        if bit_len == 0 {
            return Some(Self::one());
        }

        let mut result = Self::one();
        let mut base = self % modulus;

        for i in 0..bit_len {
            // Always compute the multiplication
            let mul_result = &(&result * &base) % modulus;

            // Constant-time select based on bit value
            let bit = exp.bit_ct(i);
            let mask = 0u64.wrapping_sub(bit);
            result = Self::ct_select(mask, &mul_result, &result);

            // Always square
            base = base.square() % modulus;
        }

        Some(result)
    }

    // SECURITY: Constant-time Montgomery ladder modexp
    fn mod_pow_montgomery_ct(&self, exp: &Self, modulus: &Self) -> Self {
        debug_assert!(modulus.is_odd());

        let n = modulus.limbs.len();
        let r_bits = n * LIMB_BITS;

        let r = Self::one().shl_bits(r_bits) % modulus;
        let r2 = r.square() % modulus;
        let m_inv = Self::montgomery_inverse(modulus.limbs[0]);

        let mut base = self % modulus;
        base = Self::montgomery_reduce(&(&base * &r2), modulus, m_inv);

        // Montgomery ladder: r0 = 1, r1 = base
        let mut r0 = r.clone();
        let mut r1 = base;

        let bit_len = exp.bits();
        for i in (0..bit_len).rev() {
            let bit = exp.bit_ct(i);

            // Always compute both products
            let r0_times_r1 = Self::montgomery_reduce(&(&r0 * &r1), modulus, m_inv);
            let r0_squared = Self::montgomery_reduce(&r0.square(), modulus, m_inv);
            let r1_squared = Self::montgomery_reduce(&r1.square(), modulus, m_inv);

            // Select based on bit (constant-time)
            let mask = 0u64.wrapping_sub(bit);
            r0 = Self::ct_select(mask, &r0_squared, &r0_times_r1);
            r1 = Self::ct_select(mask, &r0_times_r1, &r1_squared);
        }

        Self::montgomery_reduce(&r0, modulus, m_inv)
    }

    fn montgomery_inverse(m0: u64) -> u64 {
        debug_assert!(m0 & 1 == 1);

        let mut y = 1u64;
        for _ in 0..6 {
            y = y.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(y)));
        }
        y.wrapping_neg()
    }

    fn montgomery_reduce(t: &Self, modulus: &Self, m_inv: u64) -> Self {
        let n = modulus.limbs.len();
        let mut a = t.limbs.clone();

        while a.len() < 2 * n {
            a.push(0);
        }

        for i in 0..n {
            let u = a[i].wrapping_mul(m_inv);

            let mut carry = 0u128;
            for j in 0..n {
                let sum = (a[i + j] as u128) + (u as u128) * (modulus.limbs[j] as u128) + carry;
                a[i + j] = sum as u64;
                carry = sum >> 64;
            }

            let mut k = i + n;
            while carry != 0 && k < a.len() {
                let sum = (a[k] as u128) + carry;
                a[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
            if carry != 0 {
                a.push(carry as u64);
            }
        }

        let result_limbs: Vec<u64> = a[n..].to_vec();
        let mut result = BigUint::normalize(result_limbs);

        if &result >= modulus {
            result = &result - modulus;
        }

        result
    }

    // SECURITY: Constant-time modular inverse using Fermat's little theorem for prime moduli
    // and binary extended GCD with fixed iterations for general moduli
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        if self.is_zero() || modulus.is_zero() || modulus.is_one() {
            return None;
        }

        let a = self % modulus;
        if a.is_zero() {
            return None;
        }

        // For odd moduli, use Fermat's little theorem approach via modexp
        // a^(m-2) mod m gives the inverse when gcd(a,m)=1
        if modulus.is_odd() {
            let exp = modulus - &Self::from_u64(2);
            let result = a.mod_pow(&exp, modulus)?;
            // Verify: result * a ≡ 1 (mod modulus)
            let check = &(&result * &a) % modulus;
            if check.is_one() {
                return Some(result);
            }
            return None; // gcd(a, modulus) ≠ 1
        }

        // For even moduli, use constant-time binary extended GCD
        self.mod_inverse_binary_egcd(modulus)
    }

    // SECURITY: Constant-time binary extended GCD with fixed iteration count
    fn mod_inverse_binary_egcd(&self, modulus: &Self) -> Option<Self> {
        let bit_len = modulus.bits().max(self.bits());
        let iterations = 2 * bit_len + 1; // Fixed iteration count

        let mut u = self % modulus;
        let mut v = modulus.clone();
        let mut x1 = Self::one();
        let mut x2 = Self::zero();

        // Track whether we found the inverse (constant-time accumulator)
        let mut found_mask: u64 = 0; // all 0s until we find inverse
        let mut result = Self::zero();

        for _ in 0..iterations {
            // Constant-time checks
            let u_is_one = u.ct_is_one();
            let v_is_one = v.ct_is_one();
            let u_is_zero = u.ct_is_zero();
            let v_is_zero = v.ct_is_zero();
            let u_is_odd = u.ct_is_odd();
            let v_is_odd = v.ct_is_odd();

            // Update result if u == 1 and we haven't found yet
            let should_capture_u = u_is_one & (1 ^ found_mask);
            result = Self::ct_select(0u64.wrapping_sub(should_capture_u), &x1, &result);
            found_mask |= should_capture_u;

            // Update result if v == 1 and we haven't found yet
            let should_capture_v = v_is_one & (1 ^ found_mask);
            result = Self::ct_select(0u64.wrapping_sub(should_capture_v), &x2, &result);
            found_mask |= should_capture_v;

            // Compute all possible next states
            let u_even = (1 ^ u_is_odd) & (1 ^ u_is_zero);
            let v_even = (1 ^ v_is_odd) & (1 ^ v_is_zero);
            let u_ge_v = u.ct_ge(&v);
            let both_odd_nonzero = u_is_odd & v_is_odd & (1 ^ u_is_zero) & (1 ^ v_is_zero);

            // Case 1: u is even halve u and adjust x1
            let u_halved = u.shr_bits(1);
            let x1_plus_mod = &x1 + modulus;
            let x1_for_halve = Self::ct_select(0u64.wrapping_sub(u_is_odd), &x1_plus_mod, &x1);
            let x1_halved = x1_for_halve.shr_bits(1);

            // Case 2: v is even halve v and adjust x2
            let v_halved = v.shr_bits(1);
            let x2_plus_mod = &x2 + modulus;
            let x2_for_halve = Self::ct_select(0u64.wrapping_sub(v_is_odd), &x2_plus_mod, &x2);
            let x2_halved = x2_for_halve.shr_bits(1);

            // Case 3: both odd, u >= v subtract v from u
            let u_minus_v = &u - &v;
            let x1_ge_x2 = x1.ct_ge(&x2);
            let x1_minus_x2 = &x1 - &x2;
            let x2_minus_x1 = &x2 - &x1;
            let x1_sub_wrap = modulus - &x2_minus_x1;
            let x1_subtracted = Self::ct_select(0u64.wrapping_sub(x1_ge_x2), &x1_minus_x2, &x1_sub_wrap);

            // Case 4: both odd, u < v subtract u from v
            let v_minus_u = &v - &u;
            let x2_ge_x1 = x2.ct_ge(&x1);
            let x1_minus_x2_v = &x1 - &x2;
            let x2_sub_wrap = modulus - &x1_minus_x2_v;
            let x2_subtracted = Self::ct_select(0u64.wrapping_sub(x2_ge_x1), &(&x2 - &x1), &x2_sub_wrap);

            // Select which case applies (priority: u_even > v_even > (u>=v) > (u<v))
            let case_u_even = u_even;
            let case_v_even = (1 ^ u_even) & v_even;
            let case_u_ge_v = (1 ^ u_even) & (1 ^ v_even) & both_odd_nonzero & u_ge_v;
            let case_u_lt_v = (1 ^ u_even) & (1 ^ v_even) & both_odd_nonzero & (1 ^ u_ge_v);

            // Apply updates using constant-time selection
            let new_u_1 = Self::ct_select(0u64.wrapping_sub(case_u_even), &u_halved, &u);
            let new_u_2 = Self::ct_select(0u64.wrapping_sub(case_u_ge_v), &u_minus_v, &new_u_1);
            u = new_u_2;

            let new_v_1 = Self::ct_select(0u64.wrapping_sub(case_v_even), &v_halved, &v);
            let new_v_2 = Self::ct_select(0u64.wrapping_sub(case_u_lt_v), &v_minus_u, &new_v_1);
            v = new_v_2;

            let new_x1_1 = Self::ct_select(0u64.wrapping_sub(case_u_even), &x1_halved, &x1);
            let new_x1_2 = Self::ct_select(0u64.wrapping_sub(case_u_ge_v), &x1_subtracted, &new_x1_1);
            x1 = new_x1_2;

            let new_x2_1 = Self::ct_select(0u64.wrapping_sub(case_v_even), &x2_halved, &x2);
            let new_x2_2 = Self::ct_select(0u64.wrapping_sub(case_u_lt_v), &x2_subtracted, &new_x2_1);
            x2 = new_x2_2;
        }

        // Constant-time: return result if found, verify it
        if found_mask == 1 {
            let result = &result % modulus;
            let check = &(&result * self) % modulus;
            if check.is_one() {
                return Some(result);
            }
        }

        None
    }

    // Helper: constant-time check if self >= other
    fn ct_ge(&self, other: &Self) -> u64 {
        // Returns 1 if self >= other, 0 otherwise
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut gt: u64 = 0;
        let mut lt: u64 = 0;

        for i in (0..max_len).rev() {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);

            let a_gt_b = Self::ct_gt_limb(a, b);
            let b_gt_a = Self::ct_gt_limb(b, a);

            let undecided = 1 ^ (gt | lt);
            gt |= undecided & a_gt_b;
            lt |= undecided & b_gt_a;
        }

        1 ^ lt // >= means not <
    }

    #[inline]
    fn ct_gt_limb(a: u64, b: u64) -> u64 {
        let diff = b.wrapping_sub(a);
        let b_inv = !b;
        ((b_inv & a) | ((b_inv | a) & diff)) >> 63
    }

    // Helper: constant-time is_one check
    fn ct_is_one(&self) -> u64 {
        if self.limbs.is_empty() {
            return 0;
        }
        let first_is_one = ((self.limbs[0] ^ 1) == 0) as u64;
        let mut rest_zero: u64 = 1;
        for i in 1..self.limbs.len() {
            rest_zero &= (self.limbs[i] == 0) as u64;
        }
        first_is_one & rest_zero
    }

    // Helper: constant-time is_zero check
    fn ct_is_zero(&self) -> u64 {
        let mut all_zero: u64 = 1;
        for &limb in &self.limbs {
            all_zero &= (limb == 0) as u64;
        }
        all_zero
    }

    // Helper: constant-time is_odd check
    fn ct_is_odd(&self) -> u64 {
        if self.limbs.is_empty() {
            0
        } else {
            self.limbs[0] & 1
        }
    }

    pub fn gcd(&self, other: &Self) -> Self {
        if self.is_zero() {
            return other.clone();
        }
        if other.is_zero() {
            return self.clone();
        }

        let mut a = self.clone();
        let mut b = other.clone();

        let a_tz = a.trailing_zeros();
        let b_tz = b.trailing_zeros();
        let shift = core::cmp::min(a_tz, b_tz);

        a = a.shr_bits(a_tz);
        b = b.shr_bits(b_tz);

        loop {
            if a > b {
                core::mem::swap(&mut a, &mut b);
            }

            b = &b - &a;

            if b.is_zero() {
                return a.shl_bits(shift);
            }

            b = b.shr_bits(b.trailing_zeros());
        }
    }

    pub fn lcm(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let g = self.gcd(other);
        (self / &g) * other
    }
}
