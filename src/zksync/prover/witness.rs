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

use super::boojum::GoldilocksField;
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct Witness {
    pub values: Vec<GoldilocksField>,
    pub public_inputs: Vec<GoldilocksField>,
}

impl Witness {
    pub fn new() -> Self {
        Self { values: Vec::new(), public_inputs: Vec::new() }
    }

    pub fn with_capacity(private: usize, public: usize) -> Self {
        Self { values: Vec::with_capacity(private), public_inputs: Vec::with_capacity(public) }
    }

    pub fn push_private(&mut self, value: GoldilocksField) {
        self.values.push(value);
    }

    pub fn push_public(&mut self, value: GoldilocksField) {
        self.public_inputs.push(value);
    }

    pub fn extend_private(&mut self, values: &[GoldilocksField]) {
        self.values.extend_from_slice(values);
    }

    pub fn extend_public(&mut self, values: &[GoldilocksField]) {
        self.public_inputs.extend_from_slice(values);
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn public_len(&self) -> usize {
        self.public_inputs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl Default for Witness {
    fn default() -> Self {
        Self::new()
    }
}
