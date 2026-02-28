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

use super::super::BigUint;

impl BigUint {
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        if self.is_zero() || modulus.is_zero() || modulus.is_one() {
            return None;
        }

        let a = self % modulus;
        if a.is_zero() {
            return None;
        }

        if modulus.is_odd() {
            let exp = modulus - &Self::from_u64(2);
            let result = a.mod_pow(&exp, modulus)?;
            let check = &(&result * &a) % modulus;
            if check.is_one() {
                return Some(result);
            }
            return None;
        }

        self.mod_inverse_binary_egcd(modulus)
    }

    pub(crate) fn mod_inverse_binary_egcd(&self, modulus: &Self) -> Option<Self> {
        let bit_len = modulus.bits().max(self.bits());
        let iterations = 2 * bit_len + 1;

        let mut u = self % modulus;
        let mut v = modulus.clone();
        let mut x1 = Self::one();
        let mut x2 = Self::zero();

        let mut found_mask: u64 = 0;
        let mut result = Self::zero();

        for _ in 0..iterations {
            let u_is_one = u.ct_is_one();
            let v_is_one = v.ct_is_one();
            let u_is_zero = u.ct_is_zero();
            let v_is_zero = v.ct_is_zero();
            let u_is_odd = u.ct_is_odd();
            let v_is_odd = v.ct_is_odd();

            let should_capture_u = u_is_one & (1 ^ found_mask);
            result = Self::ct_select(0u64.wrapping_sub(should_capture_u), &x1, &result);
            found_mask |= should_capture_u;

            let should_capture_v = v_is_one & (1 ^ found_mask);
            result = Self::ct_select(0u64.wrapping_sub(should_capture_v), &x2, &result);
            found_mask |= should_capture_v;

            let u_even = (1 ^ u_is_odd) & (1 ^ u_is_zero);
            let v_even = (1 ^ v_is_odd) & (1 ^ v_is_zero);
            let u_ge_v = u.ct_ge(&v);
            let both_odd_nonzero = u_is_odd & v_is_odd & (1 ^ u_is_zero) & (1 ^ v_is_zero);

            let u_halved = u.shr_bits(1);
            let x1_plus_mod = &x1 + modulus;
            let x1_for_halve = Self::ct_select(0u64.wrapping_sub(u_is_odd), &x1_plus_mod, &x1);
            let x1_halved = x1_for_halve.shr_bits(1);

            let v_halved = v.shr_bits(1);
            let x2_plus_mod = &x2 + modulus;
            let x2_for_halve = Self::ct_select(0u64.wrapping_sub(v_is_odd), &x2_plus_mod, &x2);
            let x2_halved = x2_for_halve.shr_bits(1);

            let u_minus_v = &u - &v;
            let x1_ge_x2 = x1.ct_ge(&x2);
            let x1_minus_x2 = &x1 - &x2;
            let x2_minus_x1 = &x2 - &x1;
            let x1_sub_wrap = modulus - &x2_minus_x1;
            let x1_subtracted = Self::ct_select(0u64.wrapping_sub(x1_ge_x2), &x1_minus_x2, &x1_sub_wrap);

            let v_minus_u = &v - &u;
            let x2_ge_x1 = x2.ct_ge(&x1);
            let x1_minus_x2_v = &x1 - &x2;
            let x2_sub_wrap = modulus - &x1_minus_x2_v;
            let x2_subtracted = Self::ct_select(0u64.wrapping_sub(x2_ge_x1), &(&x2 - &x1), &x2_sub_wrap);

            let case_u_even = u_even;
            let case_v_even = (1 ^ u_even) & v_even;
            let case_u_ge_v = (1 ^ u_even) & (1 ^ v_even) & both_odd_nonzero & u_ge_v;
            let case_u_lt_v = (1 ^ u_even) & (1 ^ v_even) & both_odd_nonzero & (1 ^ u_ge_v);

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

        if found_mask == 1 {
            let result = &result % modulus;
            let check = &(&result * self) % modulus;
            if check.is_one() {
                return Some(result);
            }
        }

        None
    }
}
