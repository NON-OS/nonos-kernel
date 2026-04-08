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

#[derive(Debug, Clone, Copy)]
pub struct PcieSegment {
    pub base_address: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl PcieSegment {
    pub fn config_address(&self, bus: u8, device: u8, function: u8, offset: u16) -> Option<u64> {
        if bus < self.start_bus || bus > self.end_bus {
            return None;
        }
        if device >= 32 || function >= 8 || offset >= 4096 {
            return None;
        }

        let addr = self.base_address
            + ((bus as u64) << 20)
            + ((device as u64) << 15)
            + ((function as u64) << 12)
            + (offset as u64);

        Some(addr)
    }
}
