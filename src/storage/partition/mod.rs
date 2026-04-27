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

pub mod constants;
pub mod gpt;
pub mod mbr;
pub mod parser;
pub mod state;
pub mod structures;
pub mod types;
pub mod utils;

pub use constants::{mbr_types, partition_types, GPT_SIGNATURE, MBR_SIGNATURE, SECTOR_SIZE};
pub use parser::PartitionParser;
pub use state::{
    find_efi_system_partition, find_nonos_partition, get_all_detected_os, get_boot_menu_entries,
    get_disk_partitions, init, is_dual_boot_capable, scan_disk_partitions,
};
pub use structures::{GptHeader, GptPartitionEntry, Mbr, MbrPartitionEntry};
pub use types::{
    BootMenuEntry, DetectedOs, DiskPartitionInfo, FilesystemType, OsType, Partition,
    PartitionTableType, PartitionType,
};
