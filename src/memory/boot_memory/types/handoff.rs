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

use super::super::constants::*;
use super::super::error::{BootMemoryError, BootMemoryResult};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BootHandoff {
    pub magic: u64,
    pub version: u16,
    pub flags: u16,
    pub memory_base: u64,
    pub memory_size: u64,
    pub kernel_base: u64,
    pub kernel_size: u64,
    pub capsule_base: u64,
    pub capsule_size: u64,
    pub entropy: [u8; BOOT_ENTROPY_SIZE],
    pub timestamp: u64,
}

impl BootHandoff {
    pub fn validate(&self) -> BootMemoryResult<()> {
        if self.magic != BOOT_HANDOFF_MAGIC {
            return Err(BootMemoryError::InvalidHandoffMagic);
        }
        if self.version < MIN_HANDOFF_VERSION || self.version > MAX_HANDOFF_VERSION {
            return Err(BootMemoryError::UnsupportedVersion);
        }
        Ok(())
    }

    pub const fn has_capsule(&self) -> bool {
        self.capsule_size > 0
    }
}
