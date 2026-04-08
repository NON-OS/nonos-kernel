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
#[derive(Debug, Clone, Copy)]
pub struct MsixCapability {
    pub cap_id: u8,
    pub next_ptr: u8,
    pub message_control: u16,
    pub table_offset_bir: u32,
    pub pba_offset_bir: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MsixTableEntry {
    pub message_addr_low: u32,
    pub message_addr_high: u32,
    pub message_data: u32,
    pub vector_control: u32,
}

impl MsixTableEntry {
    pub const MASKED: u32 = 1 << 0;

    pub const fn new(addr: u64, data: u32) -> Self {
        Self {
            message_addr_low: addr as u32,
            message_addr_high: (addr >> 32) as u32,
            message_data: data,
            vector_control: 0,
        }
    }

    pub fn mask(&mut self) { self.vector_control |= Self::MASKED; }
    pub fn unmask(&mut self) { self.vector_control &= !Self::MASKED; }
}
