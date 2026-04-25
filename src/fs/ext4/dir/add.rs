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
use super::helpers::{find_space_in_block, write_dir_entry};

pub fn dir_add_entry(
    dev: &str,
    sb: &Ext4Superblock,
    dir_ino: u32,
    name: &str,
    ino: u32,
    ftype: u8,
) -> Result<(), i32> {
    let dir_inode = read_inode(dev, sb, dir_ino)?;
    let block_size = sb.block_size() as usize;
    let rec_len = ((8 + name.len() + 3) & !3) as u16;
    let blocks = (dir_inode.size() + block_size as u64 - 1) / block_size as u64;
    let mut buf = alloc::vec![0u8; block_size];
    for b in 0..blocks {
        let pblock = extent_lookup(dev, sb, &dir_inode, b as u32)?;
        crate::drivers::block::read(dev, &mut buf, pblock * sb.block_size() as u64)?;
        if let Some(off) = find_space_in_block(&buf, rec_len as usize) {
            write_dir_entry(&mut buf, off, ino, name, ftype);
            crate::drivers::block::write(dev, &buf, pblock * sb.block_size() as u64)?;
            return Ok(());
        }
    }
    Err(-28)
}
