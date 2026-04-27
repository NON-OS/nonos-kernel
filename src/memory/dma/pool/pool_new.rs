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

extern crate alloc;
use super::super::error::DmaResult;
use super::super::types::DmaConstraints;
use super::pool_struct::DmaPool;
use alloc::vec::Vec;

impl DmaPool {
    pub fn new(
        region_size: usize,
        capacity: usize,
        constraints: DmaConstraints,
    ) -> DmaResult<Self> {
        Ok(Self {
            regions: Vec::with_capacity(capacity),
            free_regions: Vec::with_capacity(capacity),
            constraints,
            total_size: region_size * capacity,
            allocated_count: 0,
        })
    }
}
