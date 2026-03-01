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

#[derive(Clone, Debug)]
pub struct BridgeInfo {
    pub primary_bus: u8,
    pub secondary_bus: u8,
    pub subordinate_bus: u8,
    pub io_base: u32,
    pub io_limit: u32,
    pub memory_base: u32,
    pub memory_limit: u32,
    pub prefetch_base: u64,
    pub prefetch_limit: u64,
    pub bridge_control: u16,
}

impl BridgeInfo {
    pub fn new() -> Self {
        Self {
            primary_bus: 0,
            secondary_bus: 0,
            subordinate_bus: 0,
            io_base: 0,
            io_limit: 0,
            memory_base: 0,
            memory_limit: 0,
            prefetch_base: 0,
            prefetch_limit: 0,
            bridge_control: 0,
        }
    }

    pub fn io_window(&self) -> (u32, u32) {
        (self.io_base, self.io_limit)
    }

    pub fn memory_window(&self) -> (u32, u32) {
        (self.memory_base, self.memory_limit)
    }

    pub fn prefetch_window(&self) -> (u64, u64) {
        (self.prefetch_base, self.prefetch_limit)
    }
}

impl Default for BridgeInfo {
    fn default() -> Self {
        Self::new()
    }
}
