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

use alloc::string::String;

use super::types::{
    partition_types, mbr_types, PartitionType, Partition, DetectedOs, OsType,
};

pub fn guid_to_partition_type(guid: &[u8; 16]) -> PartitionType {
    if guid == &partition_types::EFI_SYSTEM {
        PartitionType::EfiSystem
    } else if guid == &partition_types::MICROSOFT_BASIC_DATA {
        PartitionType::MicrosoftBasicData
    } else if guid == &partition_types::MICROSOFT_RESERVED {
        PartitionType::MicrosoftReserved
    } else if guid == &partition_types::LINUX_FILESYSTEM {
        PartitionType::LinuxFilesystem
    } else if guid == &partition_types::LINUX_SWAP {
        PartitionType::LinuxSwap
    } else if guid == &partition_types::LINUX_LVM {
        PartitionType::LinuxLvm
    } else if guid == &partition_types::APPLE_HFS_PLUS {
        PartitionType::AppleHfsPlus
    } else if guid == &partition_types::APPLE_APFS {
        PartitionType::AppleApfs
    } else if guid == &partition_types::NONOS_ZEROSTATE {
        PartitionType::NonosZerostate
    } else {
        PartitionType::Unknown(*guid)
    }
}

pub fn utf16le_to_string(name: &[u16; 36]) -> String {
    let mut s = String::new();
    for &ch in name {
        if ch == 0 {
            break;
        }
        if let Some(c) = char::from_u32(ch as u32) {
            s.push(c);
        }
    }
    s
}

pub fn detect_os_from_partition(partition: &Partition) -> Option<DetectedOs> {
    let os_type = match &partition.partition_type {
        PartitionType::MicrosoftBasicData | PartitionType::MicrosoftReserved => {
            Some(OsType::Windows)
        }
        PartitionType::LinuxFilesystem | PartitionType::LinuxLvm => {
            Some(OsType::Linux)
        }
        PartitionType::AppleHfsPlus | PartitionType::AppleApfs => {
            Some(OsType::MacOs)
        }
        PartitionType::NonosZerostate => {
            Some(OsType::NonOs)
        }
        PartitionType::LegacyMbr(t) => match *t {
            mbr_types::NTFS => Some(OsType::Windows),
            mbr_types::LINUX => Some(OsType::Linux),
            _ => None,
        },
        _ => None,
    }?;

    Some(DetectedOs {
        partition_number: partition.number,
        os_type,
        version: None,
        bootable: partition.bootable,
    })
}
