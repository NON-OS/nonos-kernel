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

pub const SPLICE_F_MOVE: u32 = 1;
pub const SPLICE_F_NONBLOCK: u32 = 2;
pub const SPLICE_F_MORE: u32 = 4;
pub const SPLICE_F_GIFT: u32 = 8;

pub const SYNC_FILE_RANGE_WAIT_BEFORE: u32 = 1;
pub const SYNC_FILE_RANGE_WRITE: u32 = 2;
pub const SYNC_FILE_RANGE_WAIT_AFTER: u32 = 4;

#[derive(Debug, Clone, Copy)]
pub struct SpliceFlags(pub u32);

impl SpliceFlags {
    pub fn move_pages(&self) -> bool {
        self.0 & SPLICE_F_MOVE != 0
    }
    pub fn nonblock(&self) -> bool {
        self.0 & SPLICE_F_NONBLOCK != 0
    }
    pub fn more(&self) -> bool {
        self.0 & SPLICE_F_MORE != 0
    }
    pub fn gift(&self) -> bool {
        self.0 & SPLICE_F_GIFT != 0
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoVec {
    pub iov_base: u64,
    pub iov_len: u64,
}

impl IoVec {
    pub fn is_valid(&self) -> bool {
        self.iov_base != 0 || self.iov_len == 0
    }
}
