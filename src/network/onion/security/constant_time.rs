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


pub struct ConstantTime;

impl ConstantTime {
    pub fn select_u8(condition: u8, true_val: u8, false_val: u8) -> u8 {
        let mask = condition.wrapping_sub(1);
        (true_val & !mask) | (false_val & mask)
    }

    pub fn select_u32(condition: u32, true_val: u32, false_val: u32) -> u32 {
        let mask = condition.wrapping_sub(1);
        (true_val & !mask) | (false_val & mask)
    }

    pub fn is_zero(value: u8) -> u8 {
        let mut result = value;
        result |= result >> 4;
        result |= result >> 2;
        result |= result >> 1;
        (result ^ 1) & 1
    }

    pub fn conditional_copy(condition: u8, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        let mask = condition.wrapping_sub(1);

        for i in 0..dst.len() {
            dst[i] = (src[i] & !mask) | (dst[i] & mask);
        }
    }
}
