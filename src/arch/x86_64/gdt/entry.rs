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

use crate::arch::x86_64::gdt::constants::*;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub granularity: u8,
    pub base_high: u8,
}

impl GdtEntry {
    pub const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        }
    }

    pub const fn kernel_code_64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING0 | ACCESS_TYPE_CODE_DATA | ACCESS_EXECUTABLE | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_LONG_MODE | 0x0F,
            base_high: 0,
        }
    }

    pub const fn kernel_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING0 | ACCESS_TYPE_CODE_DATA | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_SIZE_32 | 0x0F,
            base_high: 0,
        }
    }

    pub const fn user_code_64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING3 | ACCESS_TYPE_CODE_DATA | ACCESS_EXECUTABLE | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_LONG_MODE | 0x0F,
            base_high: 0,
        }
    }

    pub const fn user_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING3 | ACCESS_TYPE_CODE_DATA | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_SIZE_32 | 0x0F,
            base_high: 0,
        }
    }

    pub const fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access,
            granularity: ((limit >> 16) & 0x0F) as u8 | (flags & 0xF0),
            base_high: ((base >> 24) & 0xFF) as u8,
        }
    }

    pub const fn is_present(&self) -> bool {
        self.access & ACCESS_PRESENT != 0
    }

    pub const fn dpl(&self) -> u8 {
        (self.access >> 5) & 0x3
    }

    pub const fn is_code(&self) -> bool {
        self.access & ACCESS_TYPE_CODE_DATA != 0 && self.access & ACCESS_EXECUTABLE != 0
    }

    pub const fn is_long_mode(&self) -> bool {
        self.granularity & FLAG_LONG_MODE != 0
    }
}
