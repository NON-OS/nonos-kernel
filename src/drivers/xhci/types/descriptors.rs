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

use crate::drivers::xhci::constants::DESC_TYPE_DEVICE;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UsbDeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub bcd_usb: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub manufacturer_index: u8,
    pub product_index: u8,
    pub serial_number_index: u8,
    pub num_configurations: u8,
}

impl UsbDeviceDescriptor {
    pub fn validate(&self) -> bool {
        self.length == 18 && self.descriptor_type == DESC_TYPE_DEVICE
    }

    pub fn usb_version(&self) -> (u8, u8) {
        let major = ((self.bcd_usb >> 8) & 0xFF) as u8;
        let minor = (self.bcd_usb & 0xFF) as u8;
        (major, minor)
    }
}
