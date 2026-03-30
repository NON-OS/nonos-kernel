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

use super::super::types::DmaConstraints;
use super::pool_struct::DmaPool;

impl DmaPool {
    pub fn available(&self) -> usize {
        self.free_regions.len()
    }

    pub fn allocated(&self) -> usize {
        self.allocated_count
    }

    pub fn capacity(&self) -> usize {
        self.regions.capacity()
    }

    pub fn total_size(&self) -> usize {
        self.total_size
    }

    pub fn constraints(&self) -> DmaConstraints {
        self.constraints
    }

    pub fn is_empty(&self) -> bool {
        self.free_regions.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.free_regions.len() == self.regions.len()
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
}
