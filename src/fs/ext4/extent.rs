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

use super::inode::Ext4Inode;
use super::superblock::Ext4Superblock;

pub const EXT4_EXT_MAGIC: u16 = 0xF30A;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4ExtentHeader {
    pub eh_magic: u16, pub eh_entries: u16, pub eh_max: u16, pub eh_depth: u16, pub eh_generation: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4Extent {
    pub ee_block: u32, pub ee_len: u16, pub ee_start_hi: u16, pub ee_start_lo: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4ExtentIdx {
    pub ei_block: u32, pub ei_leaf_lo: u32, pub ei_leaf_hi: u16, pub ei_unused: u16,
}

impl Ext4Extent {
    pub fn start(&self) -> u64 { (self.ee_start_hi as u64) << 32 | self.ee_start_lo as u64 }
    pub fn len(&self) -> u32 { if self.ee_len > 32768 { self.ee_len as u32 - 32768 } else { self.ee_len as u32 } }
    pub fn is_unwritten(&self) -> bool { self.ee_len > 32768 }
}

impl Ext4ExtentIdx {
    pub fn leaf(&self) -> u64 { (self.ei_leaf_hi as u64) << 32 | self.ei_leaf_lo as u64 }
}

pub fn extent_lookup(dev: &str, sb: &Ext4Superblock, inode: &Ext4Inode, logical_block: u32) -> Result<u64, i32> {
    if !inode.uses_extents() { return legacy_block_lookup(inode, logical_block); }
    let hdr = unsafe { &*(inode.i_block.as_ptr() as *const Ext4ExtentHeader) };
    if hdr.eh_magic != EXT4_EXT_MAGIC { return Err(-5); }
    search_extent_tree(dev, sb, inode, hdr, logical_block)
}

fn search_extent_tree(dev: &str, sb: &Ext4Superblock, inode: &Ext4Inode, hdr: &Ext4ExtentHeader, lblock: u32) -> Result<u64, i32> {
    if hdr.eh_depth == 0 {
        let extents = unsafe { core::slice::from_raw_parts((hdr as *const _ as *const u8).add(12) as *const Ext4Extent, hdr.eh_entries as usize) };
        for ext in extents {
            if lblock >= ext.ee_block && lblock < ext.ee_block + ext.len() {
                return Ok(ext.start() + (lblock - ext.ee_block) as u64);
            }
        }
        return Err(-5);
    }
    let idxs = unsafe { core::slice::from_raw_parts((hdr as *const _ as *const u8).add(12) as *const Ext4ExtentIdx, hdr.eh_entries as usize) };
    let mut target_idx = &idxs[0];
    for idx in idxs { if idx.ei_block <= lblock { target_idx = idx; } else { break; } }
    let mut buf = alloc::vec![0u8; sb.block_size() as usize];
    crate::drivers::block::read(dev, &mut buf, target_idx.leaf() * sb.block_size() as u64)?;
    let child_hdr = unsafe { &*(buf.as_ptr() as *const Ext4ExtentHeader) };
    search_extent_tree(dev, sb, inode, child_hdr, lblock)
}

fn legacy_block_lookup(inode: &Ext4Inode, lblock: u32) -> Result<u64, i32> {
    if lblock < 12 { return Ok(inode.i_block[lblock as usize] as u64); }
    Err(-5)
}

pub fn extent_insert(dev: &str, sb: &Ext4Superblock, inode: &mut Ext4Inode, lblock: u32, pblock: u64, len: u32) -> Result<(), i32> {
    Ok(())
}
