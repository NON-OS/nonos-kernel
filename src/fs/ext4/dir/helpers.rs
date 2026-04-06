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

use super::types::Ext4DirEntry;

pub fn find_space_in_block(buf: &[u8], needed: usize) -> Option<usize> {
    let mut offset = 0;
    while offset < buf.len() {
        let entry = unsafe { &*(buf.as_ptr().add(offset) as *const Ext4DirEntry) };
        if entry.rec_len == 0 {
            return Some(offset);
        }
        let actual_len = ((8 + entry.name_len as usize + 3) & !3) as u16;
        if entry.rec_len as usize - actual_len as usize >= needed {
            return Some(offset);
        }
        offset += entry.rec_len as usize;
    }
    None
}

pub fn write_dir_entry(buf: &mut [u8], offset: usize, ino: u32, name: &str, ftype: u8) {
    let ptr = buf.as_mut_ptr();
    unsafe {
        let entry = &mut *(ptr.add(offset) as *mut Ext4DirEntry);
        entry.inode = ino;
        entry.name_len = name.len() as u8;
        entry.file_type = ftype;
        core::ptr::copy_nonoverlapping(name.as_ptr(), ptr.add(offset + 8), name.len());
    }
}
