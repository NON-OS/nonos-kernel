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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FanotifyEventMetadata {
    pub event_len: u32,
    pub vers: u8,
    pub reserved: u8,
    pub metadata_len: u16,
    pub mask: u64,
    pub fd: i32,
    pub pid: i32,
}

#[derive(Clone)]
pub struct FanotifyEvent {
    pub mask: u64,
    pub fd: i32,
    pub pid: u32,
    pub path: Option<alloc::string::String>,
}

impl FanotifyEvent {
    pub fn new(mask: u64, fd: i32, pid: u32) -> Self {
        Self { mask, fd, pid, path: None }
    }

    pub fn with_path(mask: u64, fd: i32, pid: u32, path: alloc::string::String) -> Self {
        Self { mask, fd, pid, path: Some(path) }
    }

    pub fn to_metadata(&self) -> FanotifyEventMetadata {
        FanotifyEventMetadata {
            event_len: core::mem::size_of::<FanotifyEventMetadata>() as u32,
            vers: 3,
            reserved: 0,
            metadata_len: 24,
            mask: self.mask,
            fd: self.fd,
            pid: self.pid as i32,
        }
    }
}

pub fn read_events(instance_id: u32, buf: &mut [u8]) -> Result<usize, i32> {
    let instance = super::init::get_instance(instance_id).ok_or(-9i32)?;
    let mut events = instance.events.lock();
    if events.is_empty() {
        return Ok(0);
    }
    let meta_size = core::mem::size_of::<FanotifyEventMetadata>();
    let mut written = 0usize;
    while !events.is_empty() && written + meta_size <= buf.len() {
        let event = events.remove(0);
        let metadata = event.to_metadata();
        let src = &metadata as *const _ as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src, buf[written..].as_mut_ptr(), meta_size);
        }
        written += meta_size;
    }
    Ok(written)
}
