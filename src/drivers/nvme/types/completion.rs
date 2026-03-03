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

use core::mem;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct CompletionEntry {
    pub dw0: u32,
    pub dw1: u32,
    pub sq_head: u16,
    pub sq_id: u16,
    pub cid: u16,
    pub status: u16,
}

impl CompletionEntry {
    pub const SIZE: usize = mem::size_of::<Self>();

    #[inline]
    pub const fn phase(&self) -> bool {
        (self.status & 1) != 0
    }

    #[inline]
    pub const fn status_code_type(&self) -> u8 {
        ((self.status >> 9) & 0x7) as u8
    }

    #[inline]
    pub const fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    #[inline]
    pub const fn status_field(&self) -> u16 {
        self.status >> 1
    }

    #[inline]
    pub const fn is_success(&self) -> bool {
        (self.status >> 1) == 0
    }

    #[inline]
    pub const fn is_error(&self) -> bool {
        !self.is_success()
    }

    #[inline]
    pub const fn more(&self) -> bool {
        (self.status & (1 << 14)) != 0
    }

    #[inline]
    pub const fn dnr(&self) -> bool {
        (self.status & (1 << 15)) != 0
    }

    #[inline]
    pub const fn result(&self) -> u64 {
        ((self.dw1 as u64) << 32) | (self.dw0 as u64)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DsmRange {
    pub context_attributes: u32,
    pub lba_count: u32,
    pub starting_lba: u64,
}

impl DsmRange {
    pub const SIZE: usize = mem::size_of::<Self>();

    pub const fn new(lba: u64, count: u32, attributes: u32) -> Self {
        Self {
            context_attributes: attributes,
            lba_count: count,
            starting_lba: lba,
        }
    }
}
