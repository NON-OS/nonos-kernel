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

#[inline]
pub(crate) fn increment_be128(v: &mut [u8; 16]) {
    // Constant-time counter increment - always processes all 16 bytes
    let mut carry: u16 = 1;
    for i in (0..16).rev() {
        let sum = v[i] as u16 + carry;
        v[i] = sum as u8;
        carry = sum >> 8;
    }
}
