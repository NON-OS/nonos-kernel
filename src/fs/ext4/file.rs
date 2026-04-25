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
use super::inode::{read_inode, write_inode};
use super::mount::Ext4MountInfo;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static OPEN_FILES: Mutex<BTreeMap<i32, Ext4OpenFile>> = Mutex::new(BTreeMap::new());

pub struct Ext4OpenFile {
    pub mount: Arc<Ext4MountInfo>,
    pub ino: u32,
    pub flags: u32,
    pub position: AtomicU64,
}

pub fn ext4_open(mount: &Arc<Ext4MountInfo>, ino: u32, flags: u32) -> Result<i32, i32> {
    let inode = read_inode(&mount.device, &mount.sb, ino)?;
    if inode.is_dir() && (flags & 0x01) != 0 {
        return Err(-21);
    }
    let fd = crate::fs::allocate_fd()?;
    let file = Ext4OpenFile { mount: mount.clone(), ino, flags, position: AtomicU64::new(0) };
    OPEN_FILES.lock().insert(fd, file);
    Ok(fd)
}

pub fn ext4_close(fd: i32) -> Result<(), i32> {
    OPEN_FILES.lock().remove(&fd).ok_or(-9)?;
    Ok(())
}

pub fn ext4_read(fd: i32, buf: &mut [u8]) -> Result<usize, i32> {
    let files = OPEN_FILES.lock();
    let file = files.get(&fd).ok_or(-9)?;
    let pos = file.position.load(Ordering::SeqCst);
    let n = super::read::ext4_read_data(&file.mount, file.ino, buf, pos)?;
    file.position.fetch_add(n as u64, Ordering::SeqCst);
    Ok(n)
}

pub fn ext4_write(fd: i32, buf: &[u8]) -> Result<usize, i32> {
    let files = OPEN_FILES.lock();
    let file = files.get(&fd).ok_or(-9)?;
    if (file.flags & 0x03) == 0 {
        return Err(-9);
    }
    let pos = file.position.load(Ordering::SeqCst);
    let n = super::write::ext4_write_data(&file.mount, file.ino, buf, pos)?;
    file.position.fetch_add(n as u64, Ordering::SeqCst);
    Ok(n)
}

pub fn ext4_truncate(mount: &Arc<Ext4MountInfo>, ino: u32, size: u64) -> Result<(), i32> {
    let mut inode = read_inode(&mount.device, &mount.sb, ino)?;
    if inode.size() > size {
        super::balloc::truncate_blocks(mount, &mut inode, size)?;
    }
    inode.set_size(size);
    write_inode(&mount.device, &mount.sb, ino, &inode)?;
    Ok(())
}

pub fn ext4_seek(fd: i32, offset: i64, whence: i32) -> Result<u64, i32> {
    let files = OPEN_FILES.lock();
    let file = files.get(&fd).ok_or(-9)?;
    let inode = read_inode(&file.mount.device, &file.mount.sb, file.ino)?;
    let cur = file.position.load(Ordering::SeqCst);
    let new_pos = match whence {
        0 => offset as u64,
        1 => (cur as i64 + offset) as u64,
        2 => (inode.size() as i64 + offset) as u64,
        _ => return Err(-22),
    };
    file.position.store(new_pos, Ordering::SeqCst);
    Ok(new_pos)
}
