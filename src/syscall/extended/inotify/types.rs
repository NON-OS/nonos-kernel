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

pub const IN_CLOEXEC: i32 = 0x80000;
pub const IN_NONBLOCK: i32 = 0x800;

pub const IN_ACCESS: u32 = 0x00000001;
pub const IN_MODIFY: u32 = 0x00000002;
pub const IN_ATTRIB: u32 = 0x00000004;
pub const IN_CLOSE_WRITE: u32 = 0x00000008;
pub const IN_CLOSE_NOWRITE: u32 = 0x00000010;
pub const IN_OPEN: u32 = 0x00000020;
pub const IN_MOVED_FROM: u32 = 0x00000040;
pub const IN_MOVED_TO: u32 = 0x00000080;
pub const IN_CREATE: u32 = 0x00000100;
pub const IN_DELETE: u32 = 0x00000200;
pub const IN_DELETE_SELF: u32 = 0x00000400;
pub const IN_MOVE_SELF: u32 = 0x00000800;

pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;
pub const IN_ALL_EVENTS: u32 = IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE |
    IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE |
    IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF;

pub const IN_ONLYDIR: u32 = 0x01000000;
pub const IN_DONT_FOLLOW: u32 = 0x02000000;
pub const IN_EXCL_UNLINK: u32 = 0x04000000;
pub const IN_MASK_CREATE: u32 = 0x10000000;
pub const IN_MASK_ADD: u32 = 0x20000000;
pub const IN_ISDIR: u32 = 0x40000000;
pub const IN_ONESHOT: u32 = 0x80000000;

pub const IN_UNMOUNT: u32 = 0x00002000;
pub const IN_Q_OVERFLOW: u32 = 0x00004000;
pub const IN_IGNORED: u32 = 0x00008000;

pub const EINVAL: i32 = 22;
pub const ENOMEM: i32 = 12;
pub const EBADF: i32 = 9;
pub const ENOENT: i32 = 2;
pub const EAGAIN: i32 = 11;
pub const ENOTDIR: i32 = 20;
pub const EEXIST: i32 = 17;

pub const MAX_INOTIFY_INSTANCES: usize = 128;
pub const MAX_WATCHES_PER_INSTANCE: usize = 8192;
pub const MAX_QUEUED_EVENTS: usize = 16384;

#[repr(C)]
#[derive(Clone)]
pub struct InotifyEvent {
    pub wd: i32,
    pub mask: u32,
    pub cookie: u32,
    pub len: u32,
}

impl InotifyEvent {
    pub fn new(wd: i32, mask: u32, cookie: u32, name: Option<&str>) -> Self {
        let len = if let Some(n) = name {
            let name_len = n.len() + 1;
            ((name_len + 3) & !3) as u32
        } else {
            0
        };

        Self { wd, mask, cookie, len }
    }

    pub fn total_size(&self) -> usize {
        core::mem::size_of::<Self>() + self.len as usize
    }
}

pub struct InotifyStats {
    pub instance_count: usize,
    pub total_watches: usize,
    pub total_queued_events: usize,
}
