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

mod constants;
mod gpt;
mod mbr;
pub mod parser;
pub mod state;
mod structures;
pub mod types;
pub mod utils;

pub use constants::{partition_types, mbr_types, SECTOR_SIZE, MBR_SIGNATURE, GPT_SIGNATURE};
pub use parser::PartitionParser;
pub use state::{
    scan_disk_partitions, get_disk_partitions, get_all_detected_os,
    find_efi_system_partition, find_nonos_partition, is_dual_boot_capable,
    get_boot_menu_entries, init,
};
pub use structures::{GptHeader, GptPartitionEntry, MbrPartitionEntry, Mbr};
pub use types::{
    PartitionTableType, Partition, PartitionType, FilesystemType,
    DiskPartitionInfo, DetectedOs, OsType, BootMenuEntry,
};
