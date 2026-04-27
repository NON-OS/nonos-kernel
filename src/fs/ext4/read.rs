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
use super::extent::extent_lookup;
use super::inode::read_inode;
use super::mount::Ext4MountInfo;
use alloc::sync::Arc;
use alloc::vec;

pub fn ext4_read_data(
    mount: &Arc<Ext4MountInfo>,
    ino: u32,
    buf: &mut [u8],
    offset: u64,
) -> Result<usize, i32> {
    let inode = read_inode(&mount.device, &mount.sb, ino)?;
    let file_size = inode.size();
    if offset >= file_size {
        return Ok(0);
    }
    let block_size = mount.sb.block_size() as u64;
    let mut bytes_read = 0usize;
    let mut pos = offset;
    let end = (offset + buf.len() as u64).min(file_size);
    while pos < end {
        let block_num = (pos / block_size) as u32;
        let block_offset = (pos % block_size) as usize;
        let pblock = extent_lookup(&mount.device, &mount.sb, &inode, block_num)?;
        let mut block_buf = vec![0u8; block_size as usize];
        if pblock == 0 {
            block_buf.fill(0);
        } else {
            crate::drivers::block::read(&mount.device, &mut block_buf, pblock * block_size)?;
        }
        let bytes_in_block = ((block_size as usize) - block_offset).min((end - pos) as usize);
        buf[bytes_read..bytes_read + bytes_in_block]
            .copy_from_slice(&block_buf[block_offset..block_offset + bytes_in_block]);
        bytes_read += bytes_in_block;
        pos += bytes_in_block as u64;
    }
    Ok(bytes_read)
}

pub fn ext4_read_block(mount: &Arc<Ext4MountInfo>, block: u64, buf: &mut [u8]) -> Result<(), i32> {
    let block_size = mount.sb.block_size() as u64;
    if buf.len() != block_size as usize {
        return Err(-22);
    }
    crate::drivers::block::read(&mount.device, buf, block * block_size)?;
    Ok(())
}

pub fn ext4_read_symlink(
    mount: &Arc<Ext4MountInfo>,
    ino: u32,
) -> Result<alloc::string::String, i32> {
    let inode = read_inode(&mount.device, &mount.sb, ino)?;
    if !inode.is_symlink() {
        return Err(-22);
    }
    let size = inode.size() as usize;
    if size <= 60 {
        let bytes =
            unsafe { core::slice::from_raw_parts(inode.i_block.as_ptr() as *const u8, size) };
        return Ok(alloc::string::String::from_utf8_lossy(bytes).into_owned());
    }
    let mut buf = vec![0u8; size];
    ext4_read_data(mount, ino, &mut buf, 0)?;
    Ok(alloc::string::String::from_utf8_lossy(&buf).into_owned())
}
