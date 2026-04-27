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

use super::types::FieldElement;

impl FieldElement {
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
}
