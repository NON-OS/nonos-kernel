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
use super::super::balloc::alloc_block;
use super::super::inode::{read_inode, write_inode};
use super::super::mount::Ext4MountInfo;
use super::parse::parse_xattr_name;
use super::types::*;
use alloc::sync::Arc;

/* DEV NOTES eK@nonos.systems
   Extended attribute set operation. Handles XATTR_CREATE and XATTR_REPLACE flags.
   Allocates xattr block if not present, finds space for new entry, writes value
   at end of block. Entry format: 16-byte header + name (4-byte aligned).
*/
pub fn ext4_setxattr(
    mount: &Arc<Ext4MountInfo>,
    ino: u32,
    name: &str,
    value: &[u8],
    flags: u32,
) -> Result<(), i32> {
    let mut inode = read_inode(&mount.device, &mount.sb, ino)?;
    let (index, attr_name) = parse_xattr_name(name)?;
    let block_size = mount.sb.block_size() as usize;

    let xattr_block = if inode.i_file_acl_lo == 0 {
        if flags & XATTR_REPLACE != 0 {
            return Err(-61);
        }
        let new_block = alloc_block(mount, 0)? as u32;
        let mut buf = alloc::vec![0u8; block_size];
        let hdr = Ext4XattrHeader {
            h_magic: EXT4_XATTR_MAGIC,
            h_refcount: 1,
            h_blocks: 1,
            h_hash: 0,
            h_checksum: 0,
            h_reserved: [0; 3],
        };
        unsafe {
            core::ptr::write(buf.as_mut_ptr() as *mut Ext4XattrHeader, hdr);
        }
        crate::drivers::block::write(&mount.device, &buf, new_block as u64 * block_size as u64)?;
        inode.i_file_acl_lo = new_block;
        write_inode(&mount.device, &mount.sb, ino, &inode)?;
        new_block
    } else {
        inode.i_file_acl_lo
    };

    let mut buf = alloc::vec![0u8; block_size];
    crate::drivers::block::read(&mount.device, &mut buf, xattr_block as u64 * block_size as u64)?;

    let hdr = unsafe { &*(buf.as_ptr() as *const Ext4XattrHeader) };
    if hdr.h_magic != EXT4_XATTR_MAGIC {
        return Err(-5);
    }

    let (offset, found_offset, value_end) = scan_entries(&buf, block_size, index, attr_name)?;

    if found_offset.is_some() && flags & XATTR_CREATE != 0 {
        return Err(-17);
    }
    if found_offset.is_none() && flags & XATTR_REPLACE != 0 {
        return Err(-61);
    }

    let entry_offset = found_offset.unwrap_or(offset);
    let value_offset = value_end.saturating_sub((value.len() + 3) & !3);

    if value_offset <= entry_offset + 16 + ((attr_name.len() + 3) & !3) {
        return Err(-28);
    }

    write_entry(&mut buf, entry_offset, value_offset, index, attr_name, value);

    if found_offset.is_none() {
        let term_offset = entry_offset + 16 + ((attr_name.len() + 3) & !3);
        if term_offset + 4 <= value_offset {
            buf[term_offset..term_offset + 4].fill(0);
        }
    }

    crate::drivers::block::write(&mount.device, &buf, xattr_block as u64 * block_size as u64)?;
    Ok(())
}

fn scan_entries(
    buf: &[u8],
    block_size: usize,
    index: u8,
    attr_name: &str,
) -> Result<(usize, Option<usize>, usize), i32> {
    let mut offset = 32usize;
    let mut found_offset: Option<usize> = None;
    let mut value_end = block_size;

    while offset < block_size - 4 {
        let entry = unsafe { &*(buf.as_ptr().add(offset) as *const Ext4XattrEntry) };
        if entry.e_name_len == 0 {
            break;
        }
        if entry.e_value_offs != 0 && (entry.e_value_offs as usize) < value_end {
            value_end = entry.e_value_offs as usize;
        }
        if entry.e_name_index == index && entry.e_name_len as usize == attr_name.len() {
            let name_start = offset + 16;
            let name_end = name_start.saturating_add(entry.e_name_len as usize);
            if name_end > buf.len() {
                break;
            }
            let entry_name = core::str::from_utf8(&buf[name_start..name_end]).unwrap_or("");
            if entry_name == attr_name {
                found_offset = Some(offset);
            }
        }
        offset += 16 + ((entry.e_name_len as usize + 3) & !3);
    }

    Ok((offset, found_offset, value_end))
}

fn write_entry(
    buf: &mut [u8],
    entry_offset: usize,
    value_offset: usize,
    index: u8,
    attr_name: &str,
    value: &[u8],
) {
    let new_entry = Ext4XattrEntry {
        e_name_len: attr_name.len() as u8,
        e_name_index: index,
        e_value_offs: value_offset as u16,
        e_value_inum: 0,
        e_value_size: value.len() as u32,
        e_hash: 0,
    };

    unsafe {
        core::ptr::write(buf.as_mut_ptr().add(entry_offset) as *mut Ext4XattrEntry, new_entry);
        core::ptr::copy_nonoverlapping(
            attr_name.as_ptr(),
            buf.as_mut_ptr().add(entry_offset + 16),
            attr_name.len(),
        );
        core::ptr::copy_nonoverlapping(
            value.as_ptr(),
            buf.as_mut_ptr().add(value_offset),
            value.len(),
        );
    }
}
