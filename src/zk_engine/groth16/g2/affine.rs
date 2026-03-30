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

use super::field_element::G2FieldElement;

#[derive(Clone, Copy)]
pub struct G2Affine {
    pub x: G2FieldElement,
    pub y: G2FieldElement,
}

impl G2Affine {
    pub fn neg(&self) -> Self {
        G2Affine { x: self.x, y: self.y.neg() }
    }
}
