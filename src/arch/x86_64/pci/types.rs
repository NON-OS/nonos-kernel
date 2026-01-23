// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarType {
    Io,
    Memory,
}

#[derive(Debug, Clone, Copy)]
pub struct PciBar {
    pub base_addr: u64,
    pub size: u64,
    pub bar_type: BarType,
    pub prefetchable: bool,
    pub is_64bit: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PciCapability {
    pub id: u8,
    pub offset: u8,
    pub next: u8,
}

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

    pub fn mask(&mut self) {
        self.vector_control |= Self::MASKED;
    }

    pub fn unmask(&mut self) {
        self.vector_control &= !Self::MASKED;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bar_type() {
        assert_eq!(BarType::Io, BarType::Io);
        assert_ne!(BarType::Io, BarType::Memory);
    }

    #[test]
    fn test_msix_entry() {
        let mut entry = MsixTableEntry::new(0x1000, 42);
        assert_eq!(entry.message_addr_low, 0x1000);
        assert_eq!(entry.message_data, 42);
        assert_eq!(entry.vector_control, 0);

        entry.mask();
        assert_eq!(entry.vector_control & MsixTableEntry::MASKED, MsixTableEntry::MASKED);

        entry.unmask();
        assert_eq!(entry.vector_control & MsixTableEntry::MASKED, 0);
    }
}
