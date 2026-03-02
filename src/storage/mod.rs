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

pub mod ahci;
pub mod block;
pub mod block_device;
pub mod crypto_storage;
pub mod fat32;
pub mod manager;
pub mod nvme;
pub mod partition;
pub mod raid;
pub mod stats;
pub mod traits;
pub mod types;
pub mod usb_msc;

pub use block::{
    init as block_init, register_device as block_register_device, unregister_device,
    get_device, device_count as block_device_count, find_device, list_devices,
    is_init as block_is_init, BlockDevice, BlockDeviceType, BlockError, BlockResult,
    BlockOps, BLOCK_SIZE, MAX_BLOCK_DEVICES,
};

pub use fat32::{
    init as fat32_init, mount, get_fs, fs_count, is_init as fat32_is_init,
    Fat32, Fat32BootSector, BOOT_SIGNATURE,
};

pub use usb_msc::{
    init as usb_msc_init, register_device as usb_msc_register_device, read_blocks, write_blocks,
    test_unit_ready, device_count as usb_msc_device_count, is_init as usb_msc_is_init,
    get_device_info,
};

pub use manager::StorageManager;
pub use stats::DeviceStatistics;
pub use traits::StorageDevice;
pub use types::{
    StorageType, PowerState, IoOperation, IoStatus, IoFlags, DeviceCapabilities,
    IoResult, IoRequest, DeviceInfo, SmartData, IoError, IoCompletionCallback,
};
