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

use crate::arch::x86_64::gdt::constants::*;
use super::entry_base::GdtEntry;

impl GdtEntry {
    pub const fn kernel_code_64() -> Self {
        Self {
            limit_low: 0xFFFF, base_low: 0, base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING0 | ACCESS_TYPE_CODE_DATA | ACCESS_EXECUTABLE | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_LONG_MODE | 0x0F,
            base_high: 0,
        }
    }

    pub const fn kernel_data() -> Self {
        Self {
            limit_low: 0xFFFF, base_low: 0, base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING0 | ACCESS_TYPE_CODE_DATA | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_SIZE_32 | 0x0F,
            base_high: 0,
        }
    }

    pub const fn user_code_64() -> Self {
        Self {
            limit_low: 0xFFFF, base_low: 0, base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING3 | ACCESS_TYPE_CODE_DATA | ACCESS_EXECUTABLE | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_LONG_MODE | 0x0F,
            base_high: 0,
        }
    }

    pub const fn user_data() -> Self {
        Self {
            limit_low: 0xFFFF, base_low: 0, base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING3 | ACCESS_TYPE_CODE_DATA | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_SIZE_32 | 0x0F,
            base_high: 0,
        }
    }
}
