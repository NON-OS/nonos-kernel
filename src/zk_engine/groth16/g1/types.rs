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

use super::super::field::FieldElement;

pub const G1_GENERATOR_X: [u64; 4] = [1, 0, 0, 0];
pub const G1_GENERATOR_Y: [u64; 4] = [2, 0, 0, 0];

#[derive(Debug, Clone, Copy)]
pub struct G1Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

#[derive(Clone, Copy)]
pub struct G1Affine {
    pub x: FieldElement,
    pub y: FieldElement,
}
