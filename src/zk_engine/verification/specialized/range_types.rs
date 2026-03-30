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

#[repr(C)]
#[derive(Clone, Debug)]
pub struct RangeProof {
    pub a: [u8; 32],
    pub s: [u8; 32],
    pub t1: [u8; 32],
    pub t2: [u8; 32],
    pub tau_x: [u8; 32],
    pub mu: [u8; 32],
    pub inner_product: [u8; 32],
    pub bit_length: u32,
}
