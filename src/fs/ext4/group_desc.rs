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

use super::superblock::Ext4Superblock;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4GroupDesc {
    pub bg_block_bitmap_lo: u32,
    pub bg_inode_bitmap_lo: u32,
    pub bg_inode_table_lo: u32,
    pub bg_free_blocks_count_lo: u16,
    pub bg_free_inodes_count_lo: u16,
    pub bg_used_dirs_count_lo: u16,
    pub bg_flags: u16,
    pub bg_exclude_bitmap_lo: u32,
    pub bg_block_bitmap_csum_lo: u16,
    pub bg_inode_bitmap_csum_lo: u16,
    pub bg_itable_unused_lo: u16,
    pub bg_checksum: u16,
    pub bg_block_bitmap_hi: u32,
    pub bg_inode_bitmap_hi: u32,
    pub bg_inode_table_hi: u32,
    pub bg_free_blocks_count_hi: u16,
    pub bg_free_inodes_count_hi: u16,
    pub bg_used_dirs_count_hi: u16,
    pub bg_itable_unused_hi: u16,
    pub bg_exclude_bitmap_hi: u32,
    pub bg_block_bitmap_csum_hi: u16,
    pub bg_inode_bitmap_csum_hi: u16,
    pub bg_reserved: u32,
}

impl Ext4GroupDesc {
    pub fn block_bitmap(&self) -> u64 {
        (self.bg_block_bitmap_hi as u64) << 32 | self.bg_block_bitmap_lo as u64
    }
    pub fn inode_bitmap(&self) -> u64 {
        (self.bg_inode_bitmap_hi as u64) << 32 | self.bg_inode_bitmap_lo as u64
    }
    pub fn inode_table(&self) -> u64 {
        (self.bg_inode_table_hi as u64) << 32 | self.bg_inode_table_lo as u64
    }
    pub fn free_blocks_count(&self) -> u32 {
        (self.bg_free_blocks_count_hi as u32) << 16 | self.bg_free_blocks_count_lo as u32
    }
    pub fn free_inodes_count(&self) -> u32 {
        (self.bg_free_inodes_count_hi as u32) << 16 | self.bg_free_inodes_count_lo as u32
    }
    pub fn used_dirs_count(&self) -> u32 {
        (self.bg_used_dirs_count_hi as u32) << 16 | self.bg_used_dirs_count_lo as u32
    }
}

pub fn read_group_desc(dev: &str, sb: &Ext4Superblock, group: u32) -> Result<Ext4GroupDesc, i32> {
    let block_size = sb.block_size();
    let desc_size = if sb.s_desc_size > 32 { sb.s_desc_size as u32 } else { 32 };
    let gd_block = if block_size == 1024 { 2 } else { 1 };
    let offset = gd_block as u64 * block_size as u64 + group as u64 * desc_size as u64;
    let mut buf = [0u8; 64];
    crate::drivers::block::read(dev, &mut buf[..desc_size as usize], offset)?;
    Ok(unsafe { core::ptr::read(buf.as_ptr() as *const Ext4GroupDesc) })
}

pub fn write_group_desc(
    dev: &str,
    sb: &Ext4Superblock,
    group: u32,
    gd: &Ext4GroupDesc,
) -> Result<(), i32> {
    let block_size = sb.block_size();
    let desc_size = if sb.s_desc_size > 32 { sb.s_desc_size as u32 } else { 32 };
    let gd_block = if block_size == 1024 { 2 } else { 1 };
    let offset = gd_block as u64 * block_size as u64 + group as u64 * desc_size as u64;
    let buf =
        unsafe { core::slice::from_raw_parts(gd as *const _ as *const u8, desc_size as usize) };
    crate::drivers::block::write(dev, buf, offset)?;
    Ok(())
}

pub fn group_for_inode(sb: &Ext4Superblock, ino: u32) -> u32 {
    (ino - 1) / sb.s_inodes_per_group
}
pub fn group_for_block(sb: &Ext4Superblock, block: u64) -> u32 {
    ((block - sb.s_first_data_block as u64) / sb.s_blocks_per_group as u64) as u32
}
