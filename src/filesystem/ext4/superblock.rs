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

#[repr(C)]
pub struct Ext4Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub r_blocks_count: u32,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub log_cluster_size: u32,
    pub blocks_per_group: u32,
    pub clusters_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub mnt_count: u16,
    pub max_mnt_count: u16,
    pub magic: u16,
    pub state: u16,
    pub errors: u16,
    pub minor_rev_level: u16,
    pub lastcheck: u32,
    pub checkinterval: u32,
    pub creator_os: u32,
    pub rev_level: u32,
    pub def_resuid: u16,
    pub def_resgid: u16,
    pub first_ino: u32,
    pub inode_size: u16,
    pub block_group_nr: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub last_mounted: [u8; 64],
    pub algorithm_usage_bitmap: u32,
}

impl Ext4Superblock {
    pub const MAGIC: u16 = 0xEF53;

    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.rev_level >= 1
    }

    pub fn block_size(&self) -> u32 {
        1024 << self.log_block_size
    }

    pub fn inode_size(&self) -> u16 {
        if self.rev_level == 0 {
            128
        } else {
            self.inode_size
        }
    }

    pub fn blocks_per_group(&self) -> u32 {
        self.blocks_per_group
    }

    pub fn inodes_per_group(&self) -> u32 {
        self.inodes_per_group
    }

    pub fn group_count(&self) -> u32 {
        (self.blocks_count + self.blocks_per_group - 1) / self.blocks_per_group
    }

    pub fn has_64bit(&self) -> bool {
        self.feature_incompat & 0x0080 != 0
    }

    pub fn has_extent(&self) -> bool {
        self.feature_incompat & 0x0040 != 0
    }

    pub fn has_flex_bg(&self) -> bool {
        self.feature_incompat & 0x0200 != 0
    }

    pub fn needs_recovery(&self) -> bool {
        self.feature_incompat & 0x0004 != 0
    }

    pub fn is_journaled(&self) -> bool {
        self.feature_compat & 0x0004 != 0
    }

    pub fn total_size(&self) -> u64 {
        if self.has_64bit() {
            ((self.blocks_count as u64) << 32) | (self.r_blocks_count as u64)
        } else {
            self.blocks_count as u64
        } * self.block_size() as u64
    }

    pub fn free_space(&self) -> u64 {
        self.free_blocks_count as u64 * self.block_size() as u64
    }
}