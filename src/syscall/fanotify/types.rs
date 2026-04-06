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

pub const FAN_ACCESS: u64 = 0x01;
pub const FAN_MODIFY: u64 = 0x02;
pub const FAN_CLOSE_WRITE: u64 = 0x08;
pub const FAN_CLOSE_NOWRITE: u64 = 0x10;
pub const FAN_OPEN: u64 = 0x20;
pub const FAN_CLASS_NOTIF: u32 = 0x00;
pub const FAN_CLASS_CONTENT: u32 = 0x04;
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x08;
pub const FAN_CLOEXEC: u32 = 0x01;
pub const FAN_NONBLOCK: u32 = 0x02;
pub const FAN_MARK_ADD: u32 = 0x01;
pub const FAN_MARK_REMOVE: u32 = 0x02;
pub const FAN_MARK_FLUSH: u32 = 0x80;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FanotifyEvent {
    pub event_len: u32,
    pub vers: u8,
    pub reserved: u8,
    pub metadata_len: u16,
    pub mask: u64,
    pub fd: i32,
    pub pid: i32,
}

#[derive(Debug, Clone, Copy)]
pub struct FanotifyFlags {
    pub flags: u32,
    pub event_f_flags: u32,
}

impl FanotifyFlags {
    pub fn is_valid(&self) -> bool {
        let class = self.flags & 0x0C;
        class == FAN_CLASS_NOTIF || class == FAN_CLASS_CONTENT || class == FAN_CLASS_PRE_CONTENT
    }
}

impl FanotifyEvent {
    pub const VERSION: u8 = 3;
    pub const METADATA_LEN: u16 = 24;

    pub fn new(mask: u64, fd: i32, pid: i32) -> Self {
        Self {
            event_len: Self::METADATA_LEN as u32,
            vers: Self::VERSION,
            reserved: 0,
            metadata_len: Self::METADATA_LEN,
            mask,
            fd,
            pid,
        }
    }
}
