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

use super::constants::BN254_MODULUS;
use super::types::FieldElement;

impl FieldElement {
    pub fn sqrt(&self) -> Option<FieldElement> {
        if self.is_zero() {
            return Some(*self);
        }
        let mut exp = BN254_MODULUS;
        Self::add_assign(&mut exp, &[1, 0, 0, 0]);
        for i in (1..4).rev() {
            exp[i - 1] |= (exp[i] & 3) << 62;
            exp[i] >>= 2;
        }
        exp[3] >>= 2;
        let candidate = self.pow(&exp);
        if candidate.square() == *self {
            Some(candidate)
        } else {
            None
        }
    }
}
