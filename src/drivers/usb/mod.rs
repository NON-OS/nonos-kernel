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

pub mod api;
pub mod backend;
pub mod cdc_eth;
pub mod class_driver;
pub mod constants;
pub mod descriptors;
pub mod device;
pub mod error;
pub mod hid;
pub mod hub;
pub mod manager;
pub mod msc;
pub mod rtl8152;

#[cfg(test)]
#[cfg(test)]
pub mod tests;

pub use api::{
    bind_driver, device_count, find_device, find_devices_by_class, find_hid_devices,
    find_mass_storage_devices, get_devices, get_stats, is_initialized, list_devices,
    print_device_tree, unbind_driver, UsbDeviceInfo,
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

pub use hid::{
    device_count as hid_device_count, get_devices as hid_devices, poll_key, poll_mouse,
    process_hid_report, register as register_hid, HidDevice, HidDeviceType, KeyEvent, MouseEvent,
};

pub use hub::{
    enumerate_port, get_hub, hub_count, init_hub_ports, poll_hub, register_hub, HubDescriptor,
    HubState, PortState, PortStatus,
};

pub mod consts {
    pub use super::constants::*;
}
