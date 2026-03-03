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
use super::endpoint::EndpointDescriptor;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct InterfaceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub b_interface_number: u8,
    pub b_alternate_setting: u8,
    pub b_num_endpoints: u8,
    pub b_interface_class: u8,
    pub b_interface_sub_class: u8,
    pub b_interface_protocol: u8,
    pub i_interface: u8,
}

impl InterfaceDescriptor {
    pub fn class_name(&self) -> &'static str {
        match self.b_interface_class {
            CLASS_AUDIO => "Audio",
            CLASS_CDC => "CDC/Communications",
            CLASS_HID => "HID",
            CLASS_PHYSICAL => "Physical",
            CLASS_IMAGE => "Image",
            CLASS_PRINTER => "Printer",
            CLASS_MASS_STORAGE => "Mass Storage",
            CLASS_HUB => "Hub",
            CLASS_CDC_DATA => "CDC Data",
            CLASS_SMART_CARD => "Smart Card",
            CLASS_VIDEO => "Video",
            CLASS_WIRELESS => "Wireless",
            CLASS_VENDOR => "Vendor-specific",
            _ => "Unknown",
        }
    }

    pub fn is_hid(&self) -> bool {
        self.b_interface_class == CLASS_HID
    }

    pub fn is_mass_storage(&self) -> bool {
        self.b_interface_class == CLASS_MASS_STORAGE
    }

    pub fn is_audio(&self) -> bool {
        self.b_interface_class == CLASS_AUDIO
    }
}

#[derive(Clone)]
pub struct UsbInterfaceInfo {
    pub iface: InterfaceDescriptor,
    pub endpoints: Vec<EndpointDescriptor>,
}

impl UsbInterfaceInfo {
    pub fn find_in_endpoint(&self, transfer_type: u8) -> Option<&EndpointDescriptor> {
        self.endpoints
            .iter()
            .find(|ep| ep.is_in() && ep.transfer_type() == transfer_type)
    }

    pub fn find_out_endpoint(&self, transfer_type: u8) -> Option<&EndpointDescriptor> {
        self.endpoints
            .iter()
            .find(|ep| ep.is_out() && ep.transfer_type() == transfer_type)
    }

    pub fn bulk_in_endpoint(&self) -> Option<&EndpointDescriptor> {
        self.find_in_endpoint(EP_TYPE_BULK)
    }

    pub fn bulk_out_endpoint(&self) -> Option<&EndpointDescriptor> {
        self.find_out_endpoint(EP_TYPE_BULK)
    }

    pub fn interrupt_in_endpoint(&self) -> Option<&EndpointDescriptor> {
        self.find_in_endpoint(EP_TYPE_INTERRUPT)
    }
}
