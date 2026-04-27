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
use super::super::inode::read_inode;
use super::super::mount::Ext4MountInfo;
use super::parse::parse_xattr_name;
use super::types::{Ext4XattrEntry, Ext4XattrHeader, EXT4_XATTR_MAGIC};
use alloc::sync::Arc;
use alloc::vec::Vec;

pub fn ext4_getxattr(mount: &Arc<Ext4MountInfo>, ino: u32, name: &str) -> Result<Vec<u8>, i32> {
    let inode = read_inode(&mount.device, &mount.sb, ino)?;
    let (index, attr_name) = parse_xattr_name(name)?;
    if inode.i_file_acl_lo == 0 {
        return Err(-61);
    }
    let block_size = mount.sb.block_size() as usize;
    let mut buf = alloc::vec![0u8; block_size];
    crate::drivers::block::read(
        &mount.device,
        &mut buf,
        inode.i_file_acl_lo as u64 * block_size as u64,
    )?;
    let hdr = unsafe { &*(buf.as_ptr() as *const Ext4XattrHeader) };
    if hdr.h_magic != EXT4_XATTR_MAGIC {
        return Err(-5);
    }
    let mut offset = 32usize;
    while offset < block_size - 4 {
        let entry = unsafe { &*(buf.as_ptr().add(offset) as *const Ext4XattrEntry) };
        if entry.e_name_len == 0 {
            break;
        }
        if entry.e_name_index == index && entry.e_name_len as usize == attr_name.len() {
            let name_start = offset + 16;
            let name_end = name_start.saturating_add(entry.e_name_len as usize);
            if name_end > buf.len() {
                break;
            }
            let entry_name = core::str::from_utf8(&buf[name_start..name_end]).unwrap_or("");
            if entry_name == attr_name {
                let val_start = entry.e_value_offs as usize;
                let val_end = val_start.checked_add(entry.e_value_size as usize).ok_or(-5i32)?;
                if val_end > buf.len() {
                    return Err(-5);
                }
                let value = buf[val_start..val_end].to_vec();
                return Ok(value);
            }
        }
        offset += 16 + ((entry.e_name_len as usize + 3) & !3);
    }
    Err(-61)
}
