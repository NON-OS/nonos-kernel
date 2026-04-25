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

#[derive(Debug, Clone, Copy, Default)]
pub struct MmioStatsSnapshot {
    pub total_regions: usize,
    pub total_mapped_size: u64,
    pub read_operations: u64,
    pub write_operations: u64,
}

impl MmioStatsSnapshot {
    pub const fn new() -> Self {
        Self { total_regions: 0, total_mapped_size: 0, read_operations: 0, write_operations: 0 }
    }

    pub const fn total_operations(&self) -> u64 {
        self.read_operations + self.write_operations
    }
}
