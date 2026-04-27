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

use super::group_desc::{group_for_inode, read_group_desc};
use super::superblock::Ext4Superblock;

pub const EXT4_ROOT_INO: u32 = 2;
pub const S_IFMT: u16 = 0xF000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFDIR: u16 = 0x4000;
pub const S_IFLNK: u16 = 0xA000;
pub const S_IFBLK: u16 = 0x6000;
pub const S_IFCHR: u16 = 0x2000;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4Inode {
    pub i_mode: u16,
    pub i_uid: u16,
    pub i_size_lo: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    pub i_gid: u16,
    pub i_links_count: u16,
    pub i_blocks_lo: u32,
    pub i_flags: u32,
    pub i_osd1: u32,
    pub i_block: [u32; 15],
    pub i_generation: u32,
    pub i_file_acl_lo: u32,
    pub i_size_high: u32,
    pub i_obso_faddr: u32,
    pub i_osd2: [u8; 12],
    pub i_extra_isize: u16,
    pub i_checksum_hi: u16,
    pub i_ctime_extra: u32,
    pub i_mtime_extra: u32,
    pub i_atime_extra: u32,
    pub i_crtime: u32,
    pub i_crtime_extra: u32,
    pub i_version_hi: u32,
    pub i_projid: u32,
}

impl Ext4Inode {
    pub fn size(&self) -> u64 {
        (self.i_size_high as u64) << 32 | self.i_size_lo as u64
    }
    pub fn set_size(&mut self, size: u64) {
        self.i_size_lo = size as u32;
        self.i_size_high = (size >> 32) as u32;
    }
    pub fn is_dir(&self) -> bool {
        (self.i_mode & S_IFMT) == S_IFDIR
    }
    pub fn is_file(&self) -> bool {
        (self.i_mode & S_IFMT) == S_IFREG
    }
    pub fn is_symlink(&self) -> bool {
        (self.i_mode & S_IFMT) == S_IFLNK
    }
    pub fn uses_extents(&self) -> bool {
        (self.i_flags & 0x80000) != 0
    }
    pub fn blocks_count(&self) -> u64 {
        self.i_blocks_lo as u64
    }
}

pub fn read_inode(dev: &str, sb: &Ext4Superblock, ino: u32) -> Result<Ext4Inode, i32> {
    if ino == 0 || ino > sb.s_inodes_count {
        return Err(-22);
    }
    let group = group_for_inode(sb, ino);
    let gd = read_group_desc(dev, sb, group)?;
    let index = (ino - 1) % sb.s_inodes_per_group;
    let inode_size = sb.s_inode_size as u64;
    let offset = gd.inode_table() * sb.block_size() as u64 + index as u64 * inode_size;
    let mut buf = [0u8; 256];
    crate::drivers::block::read(dev, &mut buf[..inode_size as usize], offset)?;
    Ok(unsafe { core::ptr::read(buf.as_ptr() as *const Ext4Inode) })
}

pub fn write_inode(dev: &str, sb: &Ext4Superblock, ino: u32, inode: &Ext4Inode) -> Result<(), i32> {
    if ino == 0 || ino > sb.s_inodes_count {
        return Err(-22);
    }
    let group = group_for_inode(sb, ino);
    let gd = read_group_desc(dev, sb, group)?;
    let index = (ino - 1) % sb.s_inodes_per_group;
    let inode_size = sb.s_inode_size as u64;
    let offset = gd.inode_table() * sb.block_size() as u64 + index as u64 * inode_size;
    let buf =
        unsafe { core::slice::from_raw_parts(inode as *const _ as *const u8, inode_size as usize) };
    crate::drivers::block::write(dev, buf, offset)?;
    Ok(())
}
