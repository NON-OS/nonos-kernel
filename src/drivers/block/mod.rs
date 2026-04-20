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

mod device;
pub mod ops;
mod registry;

pub use device::{BlockDevice, BlockDeviceInfo};
pub use ops::{open, close, read, write, flush, ioctl, is_open, open_count};
pub use registry::{register_device, unregister_device, list_disks, get_device, get_device_info, list_devices, get_device_stats, record_read, record_write, BlockIoStats};
