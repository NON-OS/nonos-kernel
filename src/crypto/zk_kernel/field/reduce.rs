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

use super::super::constants::L;
use super::types::FieldElement;

impl FieldElement {
    // SECURITY: Constant-time modular reduction using conditional subtraction.
    pub(super) fn reduce(&mut self) {
        for _ in 0..2 {
            let mut borrow: u8 = 0;
            let mut temp = [0u8; 32];

            for i in 0..32 {
                let a = self.bytes[i] as u16;
                let b = L[i] as u16 + borrow as u16;
                let diff = a.wrapping_sub(b);
                temp[i] = diff as u8;
                borrow = (diff >> 8) as u8 & 1;
            }

            let mask = borrow.wrapping_sub(1);
            for i in 0..32 {
                self.bytes[i] = (temp[i] & mask) | (self.bytes[i] & !mask);
            }
        }
    }
}
