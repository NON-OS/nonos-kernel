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
use alloc::vec;
use super::mount::Ext4MountInfo;
use super::group_desc::{read_group_desc, write_group_desc, Ext4GroupDesc};
use super::superblock::write_superblock;
use super::inode::Ext4Inode;

pub fn alloc_block(mount: &Arc<Ext4MountInfo>, goal: u64) -> Result<u64, i32> {
    let sb = &mount.sb;
    let block_size = sb.block_size() as usize;
    let groups = sb.group_count();
    let start_group = ((goal - sb.s_first_data_block as u64) / sb.s_blocks_per_group as u64) as u32;
    for i in 0..groups {
        let group = (start_group + i) % groups;
        let mut gd = read_group_desc(&mount.device, sb, group)?;
        if gd.free_blocks_count() == 0 { continue; }
        let mut bitmap = vec![0u8; block_size];
        crate::drivers::block::read(&mount.device, &mut bitmap, gd.block_bitmap() * block_size as u64)?;
        for byte_idx in 0..block_size {
            if bitmap[byte_idx] != 0xFF {
                for bit in 0..8 {
                    if (bitmap[byte_idx] & (1 << bit)) == 0 {
                        bitmap[byte_idx] |= 1 << bit;
                        crate::drivers::block::write(&mount.device, &bitmap, gd.block_bitmap() * block_size as u64)?;
                        let free = gd.free_blocks_count() - 1;
                        gd.bg_free_blocks_count_lo = free as u16;
                        write_group_desc(&mount.device, sb, group, &gd)?;
                        let block = sb.s_first_data_block as u64 + group as u64 * sb.s_blocks_per_group as u64 + byte_idx as u64 * 8 + bit as u64;
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

pub fn alloc_blocks(mount: &Arc<Ext4MountInfo>, goal: u64, count: u32) -> Result<alloc::vec::Vec<u64>, i32> {
    let mut blocks = alloc::vec::Vec::with_capacity(count as usize);
    let mut g = goal;
    for _ in 0..count {
        let b = alloc_block(mount, g)?;
        blocks.push(b);
        g = b + 1;
    }
    Ok(blocks)
}

pub fn truncate_blocks(mount: &Arc<Ext4MountInfo>, inode: &mut Ext4Inode, new_size: u64) -> Result<(), i32> {
    Ok(())
}
