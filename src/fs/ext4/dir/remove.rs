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
use super::super::extent::extent_lookup;
use super::super::inode::read_inode;
use super::super::superblock::Ext4Superblock;
use super::types::Ext4DirEntry;

/* DEV NOTES eK@nonos.systems
   Remove a directory entry by name. Reads through directory blocks, finds matching entry,
   and zeros out the inode field to mark as deleted.
*/
pub fn dir_remove_entry(
    dev: &str,
    sb: &Ext4Superblock,
    dir_ino: u32,
    name: &str,
) -> Result<(), i32> {
    let dir_inode = read_inode(dev, sb, dir_ino)?;
    if !dir_inode.is_dir() {
        return Err(-20);
    }

    let block_size = sb.block_size() as usize;
    let blocks = (dir_inode.size() + block_size as u64 - 1) / block_size as u64;
    let mut buf = alloc::vec![0u8; block_size];

    for b in 0..blocks {
        let pblock = extent_lookup(dev, sb, &dir_inode, b as u32)?;
        crate::drivers::block::read(dev, &mut buf, pblock * sb.block_size() as u64)?;

        let mut offset = 0usize;
        while offset < block_size {
            let entry = unsafe { &*(buf.as_ptr().add(offset) as *const Ext4DirEntry) };
            if entry.rec_len == 0 {
                break;
            }

            if entry.inode != 0 && entry.name_len as usize == name.len() {
                let entry_name =
                    core::str::from_utf8(&buf[offset + 8..offset + 8 + entry.name_len as usize])
                        .unwrap_or("");
                if entry_name == name {
                    unsafe {
                        let entry_mut = &mut *(buf.as_mut_ptr().add(offset) as *mut Ext4DirEntry);
                        entry_mut.inode = 0;
                    }
                    crate::drivers::block::write(dev, &buf, pblock * sb.block_size() as u64)?;
                    return Ok(());
                }
            }

            offset += entry.rec_len as usize;
        }
    }

    Err(-2)
}
