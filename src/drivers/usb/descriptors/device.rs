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

use super::super::constants::*;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DeviceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub bcd_usb: u16,
    pub b_device_class: u8,
    pub b_device_sub_class: u8,
    pub b_device_protocol: u8,
    pub b_max_packet_size0: u8,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub i_manufacturer: u8,
    pub i_product: u8,
    pub i_serial_number: u8,
    pub b_num_configurations: u8,
}

impl DeviceDescriptor {
    pub fn usb_version_string(&self) -> &'static str {
        let version = u16::from_le(self.bcd_usb);
        match version {
            0x0100 => "USB 1.0",
            0x0110 => "USB 1.1",
            0x0200 => "USB 2.0",
            0x0210 => "USB 2.1",
            0x0300 => "USB 3.0",
            0x0310 => "USB 3.1",
            0x0320 => "USB 3.2",
            _ => "Unknown",
        }
    }

    pub fn class_name(&self) -> &'static str {
        match self.b_device_class {
            CLASS_DEVICE => "Interface-defined",
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
            CLASS_MISC => "Miscellaneous",
            CLASS_VENDOR => "Vendor-specific",
            _ => "Unknown",
        }
    }

    pub fn is_high_speed_capable(&self) -> bool {
        u16::from_le(self.bcd_usb) >= 0x0200
    }

    pub fn is_super_speed_capable(&self) -> bool {
        u16::from_le(self.bcd_usb) >= 0x0300
    }
}
