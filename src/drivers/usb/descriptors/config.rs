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

use alloc::vec::Vec;

use super::super::constants::*;
use super::interface::UsbInterfaceInfo;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ConfigDescriptorHeader {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub w_total_length: u16,
    pub b_num_interfaces: u8,
    pub b_configuration_value: u8,
    pub i_configuration: u8,
    pub bm_attributes: u8,
    pub b_max_power: u8,
}

impl ConfigDescriptorHeader {
    pub fn total_length(&self) -> u16 {
        u16::from_le(self.w_total_length)
    }

    pub fn is_self_powered(&self) -> bool {
        (self.bm_attributes & 0x40) != 0
    }

    pub fn supports_remote_wakeup(&self) -> bool {
        (self.bm_attributes & 0x20) != 0
    }

    pub fn max_power_ma(&self) -> u16 {
        self.b_max_power as u16 * 2
    }
}

#[derive(Clone)]
pub struct UsbConfiguration {
    pub header: ConfigDescriptorHeader,
    pub raw: Vec<u8>,
    pub interfaces: Vec<UsbInterfaceInfo>,
}

impl UsbConfiguration {
    pub fn config_value(&self) -> u8 {
        self.header.b_configuration_value
    }

    pub fn num_interfaces(&self) -> u8 {
        self.header.b_num_interfaces
    }

    pub fn find_interface_by_class(&self, class: u8) -> Option<&UsbInterfaceInfo> {
        self.interfaces
            .iter()
            .find(|iface| iface.iface.b_interface_class == class)
    }

    pub fn find_hid_interface(&self) -> Option<&UsbInterfaceInfo> {
        self.find_interface_by_class(CLASS_HID)
    }

    pub fn find_mass_storage_interface(&self) -> Option<&UsbInterfaceInfo> {
        self.find_interface_by_class(CLASS_MASS_STORAGE)
    }
}
