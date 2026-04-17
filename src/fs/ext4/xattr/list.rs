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
use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use super::super::mount::Ext4MountInfo;
use super::super::inode::read_inode;
use super::types::*;

/* DEV NOTES eK@nonos.systems
   List all extended attribute names for an inode. Returns fully qualified names
   with namespace prefix (user., trusted., security., system.).
*/
pub fn ext4_listxattr(mount: &Arc<Ext4MountInfo>, ino: u32) -> Result<Vec<String>, i32> {
    let inode = read_inode(&mount.device, &mount.sb, ino)?;

    if inode.i_file_acl_lo == 0 {
        return Ok(Vec::new());
    }

    let block_size = mount.sb.block_size() as usize;
    let mut buf = alloc::vec![0u8; block_size];
    crate::drivers::block::read(&mount.device, &mut buf, inode.i_file_acl_lo as u64 * block_size as u64)?;

    let hdr = unsafe { &*(buf.as_ptr() as *const Ext4XattrHeader) };
    if hdr.h_magic != EXT4_XATTR_MAGIC {
        return Err(-5);
    }

    let mut names = Vec::new();
    let mut offset = 32usize;

    while offset < block_size - 4 {
        let entry = unsafe { &*(buf.as_ptr().add(offset) as *const Ext4XattrEntry) };
        if entry.e_name_len == 0 {
            break;
        }

        let name_start = offset + 16;
        let name_end = name_start.saturating_add(entry.e_name_len as usize);
        if name_end > buf.len() { break; }
        if let Ok(attr_name) = core::str::from_utf8(&buf[name_start..name_end]) {
            let prefix = index_to_prefix(entry.e_name_index);
            let mut full_name = String::from(prefix);
            full_name.push_str(attr_name);
            names.push(full_name);
        }

        offset += 16 + ((entry.e_name_len as usize + 3) & !3);
    }

    Ok(names)
}

fn index_to_prefix(index: u8) -> &'static str {
    match index {
        EXT4_XATTR_INDEX_USER => "user.",
        EXT4_XATTR_INDEX_POSIX_ACL_ACCESS => "system.posix_acl_access",
        EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT => "system.posix_acl_default",
        EXT4_XATTR_INDEX_TRUSTED => "trusted.",
        EXT4_XATTR_INDEX_SECURITY => "security.",
        EXT4_XATTR_INDEX_SYSTEM => "system.",
        _ => "",
    }
}
