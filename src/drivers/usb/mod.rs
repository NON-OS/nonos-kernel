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

mod api;
mod backend;
mod class_driver;
pub mod constants;
pub mod error;
mod descriptors;
mod device;
mod manager;
pub mod msc;
pub mod cdc_eth;
pub mod rtl8152;

#[cfg(test)]
mod tests;

pub use api::{
    device_count, find_device, find_devices_by_class, find_hid_devices, find_mass_storage_devices,
    get_devices, get_stats, is_initialized, print_device_tree,
};
pub use backend::{UsbHostBackend, XhciBackend};
pub use class_driver::{
    bind_drivers_to_device, device_matches_vid_pid, device_matches_vid_pid_list, get_class_drivers,
    interface_matches, register_class_driver, unregister_class_driver, UsbClassDriver,
};
pub use constants::*;
pub use descriptors::{
    parse_interfaces, ConfigDescriptorHeader, DeviceDescriptor, EndpointDescriptor,
    InterfaceDescriptor, UsbConfiguration, UsbInterfaceInfo, UsbStringTable,
};
pub use device::UsbDevice;
pub use manager::{get_manager, init_usb, poll_endpoint, UsbManager, UsbStats, UsbStatsSnapshot};
pub use msc::{
    get_capacity, get_msc_device, get_msc_devices, init_msc_driver, inquiry as msc_inquiry,
    query_all_capacities, query_capacity, read_blocks, read_capacity_10, read_capacity_16,
    test_unit_ready, write_blocks, InquiryResponse, MscDeviceState, StorageCapacity,
};

pub mod consts {
    pub use super::constants::*;
}
