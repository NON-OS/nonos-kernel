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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    DeviceNGnRnE,
    DeviceNGnRE,
    DeviceNGRE,
    DeviceGRE,
    NormalNC,
    NormalWT,
    NormalWB,
}

impl MemoryType {
    pub fn attr_index(&self) -> u64 {
        match self {
            Self::DeviceNGnRnE => 0,
            Self::DeviceNGnRE => 1,
            Self::DeviceNGRE => 2,
            Self::DeviceGRE => 3,
            Self::NormalNC => 4,
            Self::NormalWT => 5,
            Self::NormalWB => 6,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PageAttributes {
    pub memory_type: MemoryType,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub user: bool,
    pub global: bool,
    pub accessed: bool,
    pub dirty: bool,
    pub contiguous: bool,
}

impl PageAttributes {
    pub const fn kernel_code() -> Self {
        Self {
            memory_type: MemoryType::NormalWB,
            read: true,
            write: false,
            execute: true,
            user: false,
            global: true,
            accessed: true,
            dirty: false,
            contiguous: false,
        }
    }

    pub const fn kernel_data() -> Self {
        Self {
            memory_type: MemoryType::NormalWB,
            read: true,
            write: true,
            execute: false,
            user: false,
            global: true,
            accessed: true,
            dirty: true,
            contiguous: false,
        }
    }

    pub const fn kernel_rodata() -> Self {
        Self {
            memory_type: MemoryType::NormalWB,
            read: true,
            write: false,
            execute: false,
            user: false,
            global: true,
            accessed: true,
            dirty: false,
            contiguous: false,
        }
    }

    pub const fn user_code() -> Self {
        Self {
            memory_type: MemoryType::NormalWB,
            read: true,
            write: false,
            execute: true,
            user: true,
            global: false,
            accessed: true,
            dirty: false,
            contiguous: false,
        }
    }

    pub const fn user_data() -> Self {
        Self {
            memory_type: MemoryType::NormalWB,
            read: true,
            write: true,
            execute: false,
            user: true,
            global: false,
            accessed: true,
            dirty: true,
            contiguous: false,
        }
    }

    pub const fn device() -> Self {
        Self {
            memory_type: MemoryType::DeviceNGnRnE,
            read: true,
            write: true,
            execute: false,
            user: false,
            global: true,
            accessed: true,
            dirty: true,
            contiguous: false,
        }
    }

    pub fn to_descriptor_bits(&self) -> u64 {
        let mut bits: u64 = 0;

        bits |= self.memory_type.attr_index() << 2;

        if !self.user {
            bits |= 1 << 6;
        }

        if !self.write {
            bits |= 1 << 7;
        }

        bits |= 0b11 << 8;

        if self.accessed {
            bits |= 1 << 10;
        }

        if !self.global {
            bits |= 1 << 11;
        }

        if self.contiguous {
            bits |= 1 << 52;
        }

        if !self.execute && !self.user {
            bits |= 1 << 54;
        }

        if !self.execute && self.user {
            bits |= 1 << 53;
        }

        bits
    }
}

impl Default for PageAttributes {
    fn default() -> Self {
        Self::kernel_data()
    }
}

pub const PTE_VALID: u64 = 1 << 0;
pub const PTE_TABLE: u64 = 1 << 1;
pub const PTE_PAGE: u64 = 1 << 1;
pub const PTE_BLOCK: u64 = 0;
pub const PTE_ATTR_INDX_MASK: u64 = 0x7 << 2;
pub const PTE_NS: u64 = 1 << 5;
pub const PTE_AP_RW_EL1: u64 = 0b00 << 6;
pub const PTE_AP_RW_ALL: u64 = 0b01 << 6;
pub const PTE_AP_RO_EL1: u64 = 0b10 << 6;
pub const PTE_AP_RO_ALL: u64 = 0b11 << 6;
pub const PTE_SH_MASK: u64 = 0x3 << 8;
pub const PTE_SH_NS: u64 = 0b00 << 8;
pub const PTE_SH_OS: u64 = 0b10 << 8;
pub const PTE_SH_IS: u64 = 0b11 << 8;
pub const PTE_AF: u64 = 1 << 10;
pub const PTE_NG: u64 = 1 << 11;
pub const PTE_CONT: u64 = 1 << 52;
pub const PTE_PXN: u64 = 1 << 53;
pub const PTE_UXN: u64 = 1 << 54;
pub const PTE_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
