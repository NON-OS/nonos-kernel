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
use super::balloc::alloc_block;
use super::extent::{extent_insert, extent_lookup};
use super::inode::{read_inode, write_inode};
use super::mount::Ext4MountInfo;
use alloc::sync::Arc;
use alloc::vec;

pub fn ext4_write_data(
    mount: &Arc<Ext4MountInfo>,
    ino: u32,
    buf: &[u8],
    offset: u64,
) -> Result<usize, i32> {
    let mut inode = read_inode(&mount.device, &mount.sb, ino)?;
    let block_size = mount.sb.block_size() as u64;
    let mut bytes_written = 0usize;
    let mut pos = offset;
    let end = offset + buf.len() as u64;
    while pos < end {
        let block_num = (pos / block_size) as u32;
        let block_offset = (pos % block_size) as usize;
        let pblock = match extent_lookup(&mount.device, &mount.sb, &inode, block_num) {
            Ok(b) if b != 0 => b,
            _ => {
                let new_block = alloc_block(mount, 0)?;
                extent_insert(&mount.device, &mount.sb, &mut inode, block_num, new_block, 1)?;
                new_block
            }
        };
        let mut block_buf = vec![0u8; block_size as usize];
        if block_offset > 0 || (end - pos) < block_size {
            crate::drivers::block::read(&mount.device, &mut block_buf, pblock * block_size)?;
        }
        let bytes_in_block = ((block_size as usize) - block_offset).min((end - pos) as usize);
        block_buf[block_offset..block_offset + bytes_in_block]
            .copy_from_slice(&buf[bytes_written..bytes_written + bytes_in_block]);
        crate::drivers::block::write(&mount.device, &block_buf, pblock * block_size)?;
        bytes_written += bytes_in_block;
        pos += bytes_in_block as u64;
    }
    if end > inode.size() {
        inode.set_size(end);
    }
    inode.i_mtime = crate::sys::clock::unix_timestamp() as u32;
    write_inode(&mount.device, &mount.sb, ino, &inode)?;
    Ok(bytes_written)
}

pub fn ext4_write_block(mount: &Arc<Ext4MountInfo>, block: u64, buf: &[u8]) -> Result<(), i32> {
    let block_size = mount.sb.block_size() as u64;
    if buf.len() != block_size as usize {
        return Err(-22);
    }
    crate::drivers::block::write(&mount.device, buf, block * block_size)?;
    Ok(())
}

pub fn ext4_fallocate(
    mount: &Arc<Ext4MountInfo>,
    ino: u32,
    offset: u64,
    len: u64,
    mode: u32,
) -> Result<(), i32> {
    let mut inode = read_inode(&mount.device, &mount.sb, ino)?;
    let block_size = mount.sb.block_size() as u64;
    let start_block = offset / block_size;
    let end_block = (offset + len + block_size - 1) / block_size;
    for block_num in start_block..end_block {
        if extent_lookup(&mount.device, &mount.sb, &inode, block_num as u32).is_err() {
            let new_block = alloc_block(mount, 0)?;
            extent_insert(&mount.device, &mount.sb, &mut inode, block_num as u32, new_block, 1)?;
        }
    }
    if offset + len > inode.size() && (mode & 0x01) == 0 {
        inode.set_size(offset + len);
    }
    write_inode(&mount.device, &mount.sb, ino, &inode)?;
    Ok(())
}
