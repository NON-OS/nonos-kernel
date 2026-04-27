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
use super::inode::{write_inode, Ext4Inode};
use super::mount::Ext4MountInfo;
use alloc::sync::Arc;
use alloc::vec;

pub fn alloc_inode(mount: &Arc<Ext4MountInfo>, is_dir: bool) -> Result<u32, i32> {
    let sb = &mount.sb;
    let block_size = sb.block_size() as usize;
    let groups = sb.group_count();
    for group in 0..groups {
        let mut gd = read_group_desc(&mount.device, sb, group)?;
        if gd.free_inodes_count() == 0 {
            continue;
        }
        let bitmap_size = (sb.s_inodes_per_group + 7) / 8;
        let mut bitmap = vec![0u8; bitmap_size as usize];
        crate::drivers::block::read(
            &mount.device,
            &mut bitmap,
            gd.inode_bitmap() * block_size as u64,
        )?;
        for byte_idx in 0..bitmap_size as usize {
            if bitmap[byte_idx] != 0xFF {
                for bit in 0..8 {
                    if (bitmap[byte_idx] & (1 << bit)) == 0 {
                        bitmap[byte_idx] |= 1 << bit;
                        crate::drivers::block::write(
                            &mount.device,
                            &bitmap,
                            gd.inode_bitmap() * block_size as u64,
                        )?;
                        gd.bg_free_inodes_count_lo = (gd.free_inodes_count() - 1) as u16;
                        if is_dir {
                            gd.bg_used_dirs_count_lo += 1;
                        }
                        write_group_desc(&mount.device, sb, group, &gd)?;
                        let ino =
                            group * sb.s_inodes_per_group + byte_idx as u32 * 8 + bit as u32 + 1;
                        return Ok(ino);
                    }
                }
            }
        }
    }
    Err(-28)
}

pub fn free_inode(mount: &Arc<Ext4MountInfo>, ino: u32) -> Result<(), i32> {
    let sb = &mount.sb;
    let block_size = sb.block_size() as usize;
    let group = (ino - 1) / sb.s_inodes_per_group;
    let index = ((ino - 1) % sb.s_inodes_per_group) as usize;
    let mut gd = read_group_desc(&mount.device, sb, group)?;
    let bitmap_size = (sb.s_inodes_per_group + 7) / 8;
    let mut bitmap = vec![0u8; bitmap_size as usize];
    crate::drivers::block::read(&mount.device, &mut bitmap, gd.inode_bitmap() * block_size as u64)?;
    bitmap[index / 8] &= !(1 << (index % 8));
    crate::drivers::block::write(&mount.device, &bitmap, gd.inode_bitmap() * block_size as u64)?;
    gd.bg_free_inodes_count_lo += 1;
    write_group_desc(&mount.device, sb, group, &gd)?;
    Ok(())
}

pub fn init_inode(
    mount: &Arc<Ext4MountInfo>,
    ino: u32,
    mode: u16,
    uid: u32,
    gid: u32,
) -> Result<(), i32> {
    let now = crate::sys::clock::unix_timestamp() as u32;
    let inode = Ext4Inode {
        i_mode: mode,
        i_uid: uid as u16,
        i_size_lo: 0,
        i_atime: now,
        i_ctime: now,
        i_mtime: now,
        i_dtime: 0,
        i_gid: gid as u16,
        i_links_count: 1,
        i_blocks_lo: 0,
        i_flags: 0x80000,
        i_osd1: 0,
        i_block: [0; 15],
        i_generation: 0,
        i_file_acl_lo: 0,
        i_size_high: 0,
        i_obso_faddr: 0,
        i_osd2: [0; 12],
        i_extra_isize: 32,
        i_checksum_hi: 0,
        i_ctime_extra: 0,
        i_mtime_extra: 0,
        i_atime_extra: 0,
        i_crtime: now,
        i_crtime_extra: 0,
        i_version_hi: 0,
        i_projid: 0,
    };
    write_inode(&mount.device, &mount.sb, ino, &inode)
}
