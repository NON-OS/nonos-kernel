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
    pub eh_magic: u16,
    pub eh_entries: u16,
    pub eh_max: u16,
    pub eh_depth: u16,
    pub eh_generation: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4Extent {
    pub ee_block: u32,
    pub ee_len: u16,
    pub ee_start_hi: u16,
    pub ee_start_lo: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ext4ExtentIdx {
    pub ei_block: u32,
    pub ei_leaf_lo: u32,
    pub ei_leaf_hi: u16,
    pub ei_unused: u16,
}

impl Ext4Extent {
    pub fn start(&self) -> u64 {
        (self.ee_start_hi as u64) << 32 | self.ee_start_lo as u64
    }
    pub fn len(&self) -> u32 {
        if self.ee_len > 32768 {
            self.ee_len as u32 - 32768
        } else {
            self.ee_len as u32
        }
    }
    pub fn is_unwritten(&self) -> bool {
        self.ee_len > 32768
    }
}

impl Ext4ExtentIdx {
    pub fn leaf(&self) -> u64 {
        (self.ei_leaf_hi as u64) << 32 | self.ei_leaf_lo as u64
    }
}

pub fn extent_lookup(
    dev: &str,
    sb: &Ext4Superblock,
    inode: &Ext4Inode,
    logical_block: u32,
) -> Result<u64, i32> {
    if !inode.uses_extents() {
        return legacy_block_lookup(inode, logical_block);
    }
    let hdr = unsafe { &*(inode.i_block.as_ptr() as *const Ext4ExtentHeader) };
    if hdr.eh_magic != EXT4_EXT_MAGIC {
        return Err(-5);
    }
    search_extent_tree(dev, sb, inode, hdr, logical_block)
}

fn search_extent_tree(
    dev: &str,
    sb: &Ext4Superblock,
    inode: &Ext4Inode,
    hdr: &Ext4ExtentHeader,
    lblock: u32,
) -> Result<u64, i32> {
    if hdr.eh_depth == 0 {
        let extents = unsafe {
            core::slice::from_raw_parts(
                (hdr as *const _ as *const u8).add(12) as *const Ext4Extent,
                hdr.eh_entries as usize,
            )
        };
        for ext in extents {
            if lblock >= ext.ee_block && lblock < ext.ee_block + ext.len() {
                return Ok(ext.start() + (lblock - ext.ee_block) as u64);
            }
        }
        return Err(-5);
    }
    let idxs = unsafe {
        core::slice::from_raw_parts(
            (hdr as *const _ as *const u8).add(12) as *const Ext4ExtentIdx,
            hdr.eh_entries as usize,
        )
    };
    let mut target_idx = &idxs[0];
    for idx in idxs {
        if idx.ei_block <= lblock {
            target_idx = idx;
        } else {
            break;
        }
    }
    let mut buf = alloc::vec![0u8; sb.block_size() as usize];
    crate::drivers::block::read(dev, &mut buf, target_idx.leaf() * sb.block_size() as u64)?;
    let child_hdr = unsafe { &*(buf.as_ptr() as *const Ext4ExtentHeader) };
    search_extent_tree(dev, sb, inode, child_hdr, lblock)
}

fn legacy_block_lookup(inode: &Ext4Inode, lblock: u32) -> Result<u64, i32> {
    if lblock < 12 {
        return Ok(inode.i_block[lblock as usize] as u64);
    }
    Err(-5)
}

pub fn extent_insert(
    dev: &str,
    sb: &Ext4Superblock,
    inode: &mut Ext4Inode,
    lblock: u32,
    pblock: u64,
    len: u32,
) -> Result<(), i32> {
    if !inode.uses_extents() {
        return insert_legacy_blocks(inode, lblock, pblock, len);
    }
    let hdr = unsafe { &mut *(inode.i_block.as_mut_ptr() as *mut Ext4ExtentHeader) };
    if hdr.eh_magic != EXT4_EXT_MAGIC {
        hdr.eh_magic = EXT4_EXT_MAGIC;
        hdr.eh_entries = 0;
        hdr.eh_max = 4;
        hdr.eh_depth = 0;
        hdr.eh_generation = 0;
    }
    if hdr.eh_depth != 0 {
        return insert_extent_deep(dev, sb, hdr, lblock, pblock, len);
    }
    let extents = unsafe {
        core::slice::from_raw_parts_mut(
            (hdr as *mut _ as *mut u8).add(12) as *mut Ext4Extent,
            hdr.eh_max as usize,
        )
    };
    if hdr.eh_entries > 0 {
        let last = &mut extents[(hdr.eh_entries - 1) as usize];
        if last.ee_block + last.len() == lblock && last.start() + last.len() as u64 == pblock {
            let new_len = last.len() + len;
            if new_len <= 32768 {
                last.ee_len = new_len as u16;
                return Ok(());
            }
        }
    }
    if hdr.eh_entries >= hdr.eh_max {
        return Err(-28);
    }
    let idx = hdr.eh_entries as usize;
    extents[idx].ee_block = lblock;
    extents[idx].ee_len = len as u16;
    extents[idx].ee_start_hi = (pblock >> 32) as u16;
    extents[idx].ee_start_lo = pblock as u32;
    hdr.eh_entries += 1;
    Ok(())
}

fn insert_extent_deep(
    dev: &str,
    sb: &Ext4Superblock,
    hdr: &Ext4ExtentHeader,
    lblock: u32,
    pblock: u64,
    len: u32,
) -> Result<(), i32> {
    let idxs = unsafe {
        core::slice::from_raw_parts(
            (hdr as *const _ as *const u8).add(12) as *const Ext4ExtentIdx,
            hdr.eh_entries as usize,
        )
    };
    let mut target_idx = &idxs[0];
    for idx in idxs {
        if idx.ei_block <= lblock {
            target_idx = idx;
        } else {
            break;
        }
    }
    let block_size = sb.block_size() as usize;
    let mut buf = alloc::vec![0u8; block_size];
    crate::drivers::block::read(dev, &mut buf, target_idx.leaf() * block_size as u64)?;
    let child_hdr = unsafe { &mut *(buf.as_mut_ptr() as *mut Ext4ExtentHeader) };
    if child_hdr.eh_depth == 0 {
        let extents = unsafe {
            core::slice::from_raw_parts_mut(
                (child_hdr as *mut _ as *mut u8).add(12) as *mut Ext4Extent,
                child_hdr.eh_max as usize,
            )
        };
        if child_hdr.eh_entries >= child_hdr.eh_max {
            return Err(-28);
        }
        let idx = child_hdr.eh_entries as usize;
        extents[idx].ee_block = lblock;
        extents[idx].ee_len = len as u16;
        extents[idx].ee_start_hi = (pblock >> 32) as u16;
        extents[idx].ee_start_lo = pblock as u32;
        child_hdr.eh_entries += 1;
        crate::drivers::block::write(dev, &buf, target_idx.leaf() * block_size as u64)?;
        Ok(())
    } else {
        insert_extent_deep(dev, sb, child_hdr, lblock, pblock, len)
    }
}

fn insert_legacy_blocks(
    inode: &mut Ext4Inode,
    lblock: u32,
    pblock: u64,
    len: u32,
) -> Result<(), i32> {
    for i in 0..len {
        let block_idx = (lblock + i) as usize;
        if block_idx < 12 {
            inode.i_block[block_idx] = pblock as u32 + i;
        } else {
            return Err(-28);
        }
    }
    Ok(())
}
