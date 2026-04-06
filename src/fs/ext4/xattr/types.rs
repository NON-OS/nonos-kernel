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

pub const EXT4_XATTR_MAGIC: u32 = 0xEA020000;
pub const EXT4_XATTR_INDEX_USER: u8 = 1;
pub const EXT4_XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
pub const EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
pub const EXT4_XATTR_INDEX_TRUSTED: u8 = 4;
pub const EXT4_XATTR_INDEX_SECURITY: u8 = 6;
pub const EXT4_XATTR_INDEX_SYSTEM: u8 = 7;

pub const XATTR_CREATE: u32 = 0x1;
pub const XATTR_REPLACE: u32 = 0x2;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4XattrHeader {
    pub h_magic: u32,
    pub h_refcount: u32,
    pub h_blocks: u32,
    pub h_hash: u32,
    pub h_checksum: u32,
    pub h_reserved: [u32; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4XattrEntry {
    pub e_name_len: u8,
    pub e_name_index: u8,
    pub e_value_offs: u16,
    pub e_value_inum: u32,
    pub e_value_size: u32,
    pub e_hash: u32,
}
