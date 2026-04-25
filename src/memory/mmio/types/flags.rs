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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioFlags {
    pub cacheable: bool,
    pub write_combining: bool,
    pub user_accessible: bool,
    pub executable: bool,
}

impl MmioFlags {
    pub const fn device() -> Self {
        Self { cacheable: false, write_combining: false, user_accessible: false, executable: false }
    }

    pub const fn framebuffer() -> Self {
        Self { cacheable: false, write_combining: true, user_accessible: false, executable: false }
    }

    pub const fn user_device() -> Self {
        Self { cacheable: false, write_combining: false, user_accessible: true, executable: false }
    }

    pub fn to_vm_flags(self) -> u32 {
        let mut flags = VM_FLAG_PRESENT | VM_FLAG_WRITABLE;
        if !self.executable {
            flags |= VM_FLAG_NX;
        }
        if self.user_accessible {
            flags |= VM_FLAG_USER;
        }
        if !self.cacheable {
            flags |= VM_FLAG_CACHE_DISABLE;
        }
        if self.write_combining {
            flags |= VM_FLAG_WRITE_COMBINE;
        }
        flags
    }
}

impl Default for MmioFlags {
    fn default() -> Self {
        Self::device()
    }
}
