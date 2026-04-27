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

extern crate alloc;
use alloc::string::String;

#[derive(Clone)]
pub struct FanotifyMark {
    pub mask: u64,
    pub flags: u32,
    pub path: Option<String>,
    pub dirfd: i32,
    pub mount_id: Option<u32>,
}

impl FanotifyMark {
    pub fn new(mask: u64, flags: u32, dirfd: i32) -> Self {
        Self { mask, flags, path: None, dirfd, mount_id: None }
    }

    pub fn matches(&self, path: &str, event_mask: u64) -> bool {
        if (self.mask & event_mask) == 0 {
            return false;
        }
        match &self.path {
            Some(p) => path.starts_with(p),
            None => true,
        }
    }
}

fn read_user_string(ptr: usize) -> Result<String, i32> {
    if ptr == 0 {
        return Err(-14);
    }
    let mut buf = [0u8; 4096];
    let mut len = 0;
    while len < buf.len() {
        let b = unsafe { *(ptr as *const u8).add(len) };
        if b == 0 {
            break;
        }
        buf[len] = b;
        len += 1;
    }
    String::from_utf8(buf[..len].to_vec()).map_err(|_| -22)
}

pub fn sys_fanotify_mark(
    fanotify_fd: i32,
    flags: u32,
    mask: u64,
    dirfd: i32,
    pathname: usize,
) -> i64 {
    let instance = match super::init::get_by_fd(fanotify_fd) {
        Some(i) => i,
        None => return -9,
    };
    let action = flags & (super::FAN_MARK_ADD | super::FAN_MARK_REMOVE | super::FAN_MARK_FLUSH);
    if action == 0 {
        return -22;
    }
    if (flags & super::FAN_MARK_FLUSH) != 0 {
        instance.marks.lock().clear();
        return 0;
    }
    let path = if pathname != 0 {
        match read_user_string(pathname) {
            Ok(s) => Some(s),
            Err(_) => return -14,
        }
    } else {
        None
    };
    let mut marks = instance.marks.lock();
    if (flags & super::FAN_MARK_ADD) != 0 {
        let mut mark = FanotifyMark::new(mask, flags, dirfd);
        mark.path = path;
        marks.push(mark);
    } else if (flags & super::FAN_MARK_REMOVE) != 0 {
        marks.retain(|m| if let (Some(p1), Some(p2)) = (&m.path, &path) { p1 != p2 } else { true });
    }
    0
}
