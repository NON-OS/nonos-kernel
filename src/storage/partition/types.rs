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

use alloc::{string::String, vec::Vec};
use super::constants::mbr_types;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionTableType {
    Gpt,
    Mbr,
    None,
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub number: u32,
    pub start_lba: u64,
    pub end_lba: u64,
    pub size_sectors: u64,
    pub size_bytes: u64,
    pub partition_type: PartitionType,
    pub name: String,
    pub guid: Option<[u8; 16]>,
    pub bootable: bool,
    pub active: bool,
    pub filesystem: Option<FilesystemType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    EfiSystem,
    MicrosoftBasicData,
    MicrosoftReserved,
    LinuxFilesystem,
    LinuxSwap,
    LinuxLvm,
    AppleHfsPlus,
    AppleApfs,
    NonosZerostate,
    Unknown([u8; 16]),
    LegacyMbr(u8),
}

impl PartitionType {
    pub fn name(&self) -> &'static str {
        match self {
            PartitionType::EfiSystem => "EFI System Partition",
            PartitionType::MicrosoftBasicData => "Microsoft Basic Data",
            PartitionType::MicrosoftReserved => "Microsoft Reserved",
            PartitionType::LinuxFilesystem => "Linux Filesystem",
            PartitionType::LinuxSwap => "Linux Swap",
            PartitionType::LinuxLvm => "Linux LVM",
            PartitionType::AppleHfsPlus => "Apple HFS+",
            PartitionType::AppleApfs => "Apple APFS",
            PartitionType::NonosZerostate => "NONOS ZeroState",
            PartitionType::Unknown(_) => "Unknown",
            PartitionType::LegacyMbr(t) => match *t {
                mbr_types::FAT12 => "FAT12",
                mbr_types::FAT16 | mbr_types::FAT16_SMALL | mbr_types::FAT16_LBA => "FAT16",
                mbr_types::FAT32 | mbr_types::FAT32_LBA => "FAT32",
                mbr_types::NTFS => "NTFS",
                mbr_types::LINUX => "Linux",
                mbr_types::LINUX_SWAP => "Linux Swap",
                mbr_types::LINUX_LVM => "Linux LVM",
                mbr_types::EFI_SYSTEM => "EFI System",
                _ => "Unknown MBR Type",
            },
        }
    }

    pub fn is_bootable_type(&self) -> bool {
        matches!(
            self,
            PartitionType::EfiSystem
                | PartitionType::MicrosoftBasicData
                | PartitionType::LinuxFilesystem
                | PartitionType::AppleHfsPlus
                | PartitionType::AppleApfs
                | PartitionType::NonosZerostate
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemType {
    Fat12,
    Fat16,
    Fat32,
    Ntfs,
    Ext2,
    Ext3,
    Ext4,
    Btrfs,
    Xfs,
    HfsPlus,
    Apfs,
    NonosRamfs,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DiskPartitionInfo {
    pub table_type: PartitionTableType,
    pub disk_guid: Option<[u8; 16]>,
    pub total_sectors: u64,
    pub sector_size: u32,
    pub partitions: Vec<Partition>,
    pub dual_boot_capable: bool,
    pub detected_os: Vec<DetectedOs>,
}

#[derive(Debug, Clone)]
pub struct DetectedOs {
    pub partition_number: u32,
    pub os_type: OsType,
    pub version: Option<String>,
    pub bootable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    Windows,
    Linux,
    MacOs,
    NonOs,
    FreeBsd,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct BootMenuEntry {
    pub name: String,
    pub disk_id: u32,
    pub partition_number: u32,
    pub os_type: OsType,
    pub is_default: bool,
    pub boot_loader_path: Option<String>,
}

impl BootMenuEntry {
    pub fn get_boot_loader_path(os_type: OsType) -> Option<String> {
        match os_type {
            OsType::Windows => Some(String::from("\\EFI\\Microsoft\\Boot\\bootmgfw.efi")),
            OsType::Linux => Some(String::from("\\EFI\\ubuntu\\grubx64.efi")),
            OsType::MacOs => Some(String::from("\\System\\Library\\CoreServices\\boot.efi")),
            OsType::FreeBsd => Some(String::from("\\EFI\\freebsd\\loader.efi")),
            _ => None,
        }
    }
}
