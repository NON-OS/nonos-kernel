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

pub use super::constants::*;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32BootSector {
    pub jump: [u8; 3],
    pub oem_name: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entry_count: u16,
    pub total_sectors_16: u16,
    pub media_type: u8,
    pub fat_size_16: u16,
    pub sectors_per_track: u16,
    pub num_heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    pub fat_size_32: u32,
    pub ext_flags: u16,
    pub fs_version: u16,
    pub root_cluster: u32,
    pub fs_info: u16,
    pub backup_boot: u16,
    pub reserved: [u8; 12],
    pub drive_num: u8,
    pub reserved1: u8,
    pub boot_sig: u8,
    pub vol_id: u32,
    pub vol_label: [u8; 11],
    pub fs_type: [u8; 8],
}

impl Fat32BootSector {
    pub fn is_valid(&self) -> bool {
        if self.bytes_per_sector != 512 && self.bytes_per_sector != 1024
           && self.bytes_per_sector != 2048 && self.bytes_per_sector != 4096 {
            return false;
        }

        if self.sectors_per_cluster == 0 || !self.sectors_per_cluster.is_power_of_two() {
            return false;
        }

        if self.fat_size_16 != 0 {
            return false;
        }

        if self.root_entry_count != 0 {
            return false;
        }

        true
    }

    pub fn cluster_size(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    pub fn first_data_sector(&self) -> u32 {
        self.reserved_sectors as u32 + (self.num_fats as u32 * self.fat_size_32)
    }

    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.first_data_sector() + (cluster - 2) * self.sectors_per_cluster as u32
    }

    pub fn fat_sector_for_cluster(&self, cluster: u32) -> u32 {
        self.reserved_sectors as u32 + (cluster * 4) / self.bytes_per_sector as u32
    }

    pub fn fat_offset_in_sector(&self, cluster: u32) -> u32 {
        (cluster * 4) % self.bytes_per_sector as u32
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub name: [u8; 8],
    pub ext: [u8; 3],
    pub attr: u8,
    pub nt_reserved: u8,
    pub create_time_tenth: u8,
    pub create_time: u16,
    pub create_date: u16,
    pub access_date: u16,
    pub first_cluster_hi: u16,
    pub write_time: u16,
    pub write_date: u16,
    pub first_cluster_lo: u16,
    pub file_size: u32,
}

impl DirEntry {
    pub fn is_free(&self) -> bool {
        self.name[0] == DIR_ENTRY_FREE || self.name[0] == DIR_ENTRY_END
    }

    pub fn is_end(&self) -> bool {
        self.name[0] == DIR_ENTRY_END
    }

    pub fn is_directory(&self) -> bool {
        (self.attr & ATTR_DIRECTORY) != 0
    }

    pub fn is_volume_label(&self) -> bool {
        (self.attr & ATTR_VOLUME_ID) != 0
    }

    pub fn is_long_name(&self) -> bool {
        self.attr == ATTR_LONG_NAME
    }

    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | (self.first_cluster_lo as u32)
    }

    pub fn get_short_name(&self, buf: &mut [u8; 13]) -> usize {
        let mut len = 0;

        for i in 0..8 {
            if self.name[i] != b' ' {
                buf[len] = self.name[i];
                len += 1;
            }
        }

        if self.ext[0] != b' ' {
            buf[len] = b'.';
            len += 1;
            for i in 0..3 {
                if self.ext[i] != b' ' {
                    buf[len] = self.ext[i];
                    len += 1;
                }
            }
        }

        len
    }

    pub fn name_matches(&self, name: &[u8]) -> bool {
        let mut buf = [0u8; 13];
        let len = self.get_short_name(&mut buf);

        if len != name.len() {
            return false;
        }

        for i in 0..len {
            let a = if buf[i] >= b'a' && buf[i] <= b'z' { buf[i] - 32 } else { buf[i] };
            let b = if name[i] >= b'a' && name[i] <= b'z' { name[i] - 32 } else { name[i] };
            if a != b {
                return false;
            }
        }

        true
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LfnEntry {
    pub order: u8,
    pub name1: [u16; 5],
    pub attr: u8,
    pub entry_type: u8,
    pub checksum: u8,
    pub name2: [u16; 6],
    pub zero: u16,
    pub name3: [u16; 2],
}

#[derive(Clone, Copy)]
pub struct Fat32 {
    pub device_id: u8,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub fat_size: u32,
    pub root_cluster: u32,
    pub total_sectors: u32,
    pub first_data_sector: u32,
    pub cluster_size: u32,
}

impl Fat32 {
    pub const fn empty() -> Self {
        Self {
            device_id: 0xFF,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 0,
            num_fats: 2,
            fat_size: 0,
            root_cluster: 2,
            total_sectors: 0,
            first_data_sector: 0,
            cluster_size: 512,
        }
    }

    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.first_data_sector + (cluster - 2) * self.sectors_per_cluster as u32
    }

    pub fn fat_sector(&self, cluster: u32) -> u32 {
        self.reserved_sectors as u32 + (cluster * 4) / self.bytes_per_sector as u32
    }

    pub fn fat_offset(&self, cluster: u32) -> u32 {
        (cluster * 4) % self.bytes_per_sector as u32
    }
}
