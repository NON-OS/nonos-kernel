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

use crate::npkg::types::Package;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Manifest {
    pub package: Package,
    pub(super) raw: Vec<u8>,
}

impl Manifest {
    pub fn new(package: Package) -> Self {
        Self { package, raw: Vec::new() }
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}
