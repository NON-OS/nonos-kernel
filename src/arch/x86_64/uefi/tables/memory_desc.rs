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
pub struct MemoryDescriptor {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

impl MemoryDescriptor {
    pub const EFI_MEMORY_UC: u64 = 0x0000000000000001;
    pub const EFI_MEMORY_WC: u64 = 0x0000000000000002;
    pub const EFI_MEMORY_WT: u64 = 0x0000000000000004;
    pub const EFI_MEMORY_WB: u64 = 0x0000000000000008;
    pub const EFI_MEMORY_UCE: u64 = 0x0000000000000010;
    pub const EFI_MEMORY_WP: u64 = 0x0000000000001000;
    pub const EFI_MEMORY_RP: u64 = 0x0000000000002000;
    pub const EFI_MEMORY_XP: u64 = 0x0000000000004000;
    pub const EFI_MEMORY_NV: u64 = 0x0000000000008000;
    pub const EFI_MEMORY_MORE_RELIABLE: u64 = 0x0000000000010000;
    pub const EFI_MEMORY_RO: u64 = 0x0000000000020000;
    pub const EFI_MEMORY_SP: u64 = 0x0000000000040000;
    pub const EFI_MEMORY_CPU_CRYPTO: u64 = 0x0000000000080000;
    pub const EFI_MEMORY_RUNTIME: u64 = 0x8000000000000000;

    pub fn size_bytes(&self) -> u64 {
        self.number_of_pages * 4096
    }
    pub fn end_address(&self) -> u64 {
        self.physical_start + self.size_bytes()
    }
    pub fn is_runtime(&self) -> bool {
        self.attribute & Self::EFI_MEMORY_RUNTIME != 0
    }
    pub fn is_usable(&self) -> bool {
        matches!(self.memory_type, 7 | 1 | 2 | 3 | 4)
    }
}
