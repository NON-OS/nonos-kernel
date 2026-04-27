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
use super::group_desc::{read_group_desc, write_group_desc};
use super::inode::Ext4Inode;
use super::mount::Ext4MountInfo;
use alloc::sync::Arc;
use alloc::vec;

pub fn alloc_block(mount: &Arc<Ext4MountInfo>, goal: u64) -> Result<u64, i32> {
    let sb = &mount.sb;
    let block_size = sb.block_size() as usize;
    let groups = sb.group_count();
    let start_group = ((goal - sb.s_first_data_block as u64) / sb.s_blocks_per_group as u64) as u32;
    for i in 0..groups {
        let group = (start_group + i) % groups;
        let mut gd = read_group_desc(&mount.device, sb, group)?;
        if gd.free_blocks_count() == 0 {
            continue;
        }
        let mut bitmap = vec![0u8; block_size];
        crate::drivers::block::read(
            &mount.device,
            &mut bitmap,
            gd.block_bitmap() * block_size as u64,
        )?;
        for byte_idx in 0..block_size {
            if bitmap[byte_idx] != 0xFF {
                for bit in 0..8 {
                    if (bitmap[byte_idx] & (1 << bit)) == 0 {
                        bitmap[byte_idx] |= 1 << bit;
                        crate::drivers::block::write(
                            &mount.device,
                            &bitmap,
                            gd.block_bitmap() * block_size as u64,
                        )?;
                        let free = gd.free_blocks_count() - 1;
                        gd.bg_free_blocks_count_lo = free as u16;
                        write_group_desc(&mount.device, sb, group, &gd)?;
                        let block = sb.s_first_data_block as u64
                            + group as u64 * sb.s_blocks_per_group as u64
                            + byte_idx as u64 * 8
                            + bit as u64;
                        return Ok(block);
                    }
                }
            }
        }
    }
    Err(-28)
}

pub fn free_block(mount: &Arc<Ext4MountInfo>, block: u64) -> Result<(), i32> {
    let sb = &mount.sb;
    let block_size = sb.block_size() as usize;
    let group = ((block - sb.s_first_data_block as u64) / sb.s_blocks_per_group as u64) as u32;
    let index = ((block - sb.s_first_data_block as u64) % sb.s_blocks_per_group as u64) as usize;
    let mut gd = read_group_desc(&mount.device, sb, group)?;
    let mut bitmap = vec![0u8; block_size];
    crate::drivers::block::read(&mount.device, &mut bitmap, gd.block_bitmap() * block_size as u64)?;
    bitmap[index / 8] &= !(1 << (index % 8));
    crate::drivers::block::write(&mount.device, &bitmap, gd.block_bitmap() * block_size as u64)?;
    gd.bg_free_blocks_count_lo += 1;
    write_group_desc(&mount.device, sb, group, &gd)?;
    Ok(())
}

pub fn alloc_blocks(
    mount: &Arc<Ext4MountInfo>,
    goal: u64,
    count: u32,
) -> Result<alloc::vec::Vec<u64>, i32> {
    let mut blocks = alloc::vec::Vec::with_capacity(count as usize);
    let mut g = goal;
    for _ in 0..count {
        let b = alloc_block(mount, g)?;
        blocks.push(b);
        g = b + 1;
    }
    Ok(blocks)
}

pub fn truncate_blocks(
    mount: &Arc<Ext4MountInfo>,
    inode: &mut Ext4Inode,
    new_size: u64,
) -> Result<(), i32> {
    let block_size = mount.sb.block_size() as u64;
    let new_blocks = (new_size + block_size - 1) / block_size;
    let old_blocks = (inode.size() + block_size - 1) / block_size;
    if new_blocks >= old_blocks {
        return Ok(());
    }
    if inode.uses_extents() {
        truncate_extents(mount, inode, new_blocks as u32)?;
    } else {
        for i in new_blocks..old_blocks.min(12) {
            let block = inode.i_block[i as usize] as u64;
            if block != 0 {
                free_block(mount, block)?;
                inode.i_block[i as usize] = 0;
            }
        }
        if old_blocks > 12 {
            truncate_indirect(mount, inode, new_blocks)?;
        }
    }
    inode.set_size(new_size);
    Ok(())
}

fn truncate_extents(
    mount: &Arc<Ext4MountInfo>,
    inode: &mut Ext4Inode,
    new_blocks: u32,
) -> Result<(), i32> {
    let hdr = unsafe { &mut *(inode.i_block.as_mut_ptr() as *mut super::extent::Ext4ExtentHeader) };
    if hdr.eh_magic != super::extent::EXT4_EXT_MAGIC {
        return Err(-5);
    }
    let extents = unsafe {
        core::slice::from_raw_parts_mut(
            (hdr as *mut _ as *mut u8).add(12) as *mut super::extent::Ext4Extent,
            hdr.eh_entries as usize,
        )
    };
    let mut new_count = 0u16;
    for ext in extents.iter_mut() {
        if ext.ee_block >= new_blocks {
            let pblock = ext.start();
            for i in 0..ext.len() {
                free_block(mount, pblock + i as u64)?;
            }
        } else if ext.ee_block + ext.len() > new_blocks {
            let keep = new_blocks - ext.ee_block;
            let pblock = ext.start();
            for i in keep..ext.len() {
                free_block(mount, pblock + i as u64)?;
            }
            ext.ee_len = keep as u16;
            new_count += 1;
        } else {
            new_count += 1;
        }
    }
    hdr.eh_entries = new_count;
    Ok(())
}

fn truncate_indirect(
    mount: &Arc<Ext4MountInfo>,
    inode: &mut Ext4Inode,
    new_blocks: u64,
) -> Result<(), i32> {
    let block_size = mount.sb.block_size() as usize;
    let ptrs_per_block = block_size / 4;
    if new_blocks < 12 && inode.i_block[12] != 0 {
        let indirect_block = inode.i_block[12] as u64;
        let mut buf = vec![0u8; block_size];
        crate::drivers::block::read(&mount.device, &mut buf, indirect_block * block_size as u64)?;
        for i in 0..ptrs_per_block {
            let ptr =
                u32::from_le_bytes([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]]);
            if ptr != 0 {
                free_block(mount, ptr as u64)?;
            }
        }
        free_block(mount, indirect_block)?;
        inode.i_block[12] = 0;
    }
    if new_blocks < 12 + ptrs_per_block as u64 && inode.i_block[13] != 0 {
        free_double_indirect(mount, inode.i_block[13] as u64)?;
        inode.i_block[13] = 0;
    }
    if new_blocks < 12 + ptrs_per_block as u64 + (ptrs_per_block * ptrs_per_block) as u64
        && inode.i_block[14] != 0
    {
        free_triple_indirect(mount, inode.i_block[14] as u64)?;
        inode.i_block[14] = 0;
    }
    Ok(())
}

fn free_double_indirect(mount: &Arc<Ext4MountInfo>, block: u64) -> Result<(), i32> {
    let block_size = mount.sb.block_size() as usize;
    let ptrs_per_block = block_size / 4;
    let mut buf = vec![0u8; block_size];
    crate::drivers::block::read(&mount.device, &mut buf, block * block_size as u64)?;
    for i in 0..ptrs_per_block {
        let ptr = u32::from_le_bytes([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]]);
        if ptr != 0 {
            let mut ibuf = vec![0u8; block_size];
            crate::drivers::block::read(&mount.device, &mut ibuf, ptr as u64 * block_size as u64)?;
            for j in 0..ptrs_per_block {
                let dptr = u32::from_le_bytes([
                    ibuf[j * 4],
                    ibuf[j * 4 + 1],
                    ibuf[j * 4 + 2],
                    ibuf[j * 4 + 3],
                ]);
                if dptr != 0 {
                    free_block(mount, dptr as u64)?;
                }
            }
            free_block(mount, ptr as u64)?;
        }
    }
    free_block(mount, block)
}

fn free_triple_indirect(mount: &Arc<Ext4MountInfo>, block: u64) -> Result<(), i32> {
    let block_size = mount.sb.block_size() as usize;
    let ptrs_per_block = block_size / 4;
    let mut buf = vec![0u8; block_size];
    crate::drivers::block::read(&mount.device, &mut buf, block * block_size as u64)?;
    for i in 0..ptrs_per_block {
        let ptr = u32::from_le_bytes([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]]);
        if ptr != 0 {
            free_double_indirect(mount, ptr as u64)?;
        }
    }
    free_block(mount, block)
}
