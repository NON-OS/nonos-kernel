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

use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy)]
pub(crate) struct VfsEntry {
    pub name: [u8; 32],
    pub name_len: u8,
    pub is_dir: bool,
    pub size: u32,
    pub parent_dir: u8,
}

pub(super) const MAX_VFS_ENTRIES: usize = 64;

pub(super) static mut VFS_ENTRIES: [VfsEntry; MAX_VFS_ENTRIES] = [VfsEntry {
    name: [0u8; 32],
    name_len: 0,
    is_dir: false,
    size: 0,
    parent_dir: 0,
}; MAX_VFS_ENTRIES];

pub(super) static VFS_COUNT: AtomicU8 = AtomicU8::new(0);

pub(crate) fn init_vfs() {
    let entries: [(&[u8], bool, u32, u8); 16] = [
        (b"home", true, 0, 0),
        (b"documents", true, 0, 0),
        (b"downloads", true, 0, 0),
        (b"pictures", true, 0, 0),
        (b"capsules", true, 0, 0),
        (b"tmp", true, 0, 0),
        (b".config", false, 256, 1),
        (b".vault", false, 128, 1),
        (b"notes.txt", false, 1024, 1),
        (b"readme.txt", false, 512, 2),
        (b"todo.md", false, 256, 2),
        (b"passwords.enc", false, 64, 2),
        (b"setup.bin", false, 8192, 3),
        (b"photo.png", false, 65536, 4),
        (b"firefox.cap", false, 2048, 5),
        (b"vault.cap", false, 1024, 5),
    ];

    unsafe {
        for (i, (name, is_dir, size, parent)) in entries.iter().enumerate() {
            let len = name.len().min(31);
            VFS_ENTRIES[i].name[..len].copy_from_slice(&name[..len]);
            VFS_ENTRIES[i].name_len = len as u8;
            VFS_ENTRIES[i].is_dir = *is_dir;
            VFS_ENTRIES[i].size = *size;
            VFS_ENTRIES[i].parent_dir = *parent;
        }
    }
    VFS_COUNT.store(entries.len() as u8, Ordering::SeqCst);
}
