// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::descriptors::{
    DeviceDescriptor, UsbStringTable, UsbConfiguration, UsbInterfaceInfo,
};
use super::constants::*;

#[derive(Clone)]
pub struct UsbDevice {
    pub slot_id: u8,
    pub addr: u8,
    pub dev_desc: DeviceDescriptor,
    pub strings: UsbStringTable,
    pub active_config: Option<UsbConfiguration>,
}

impl UsbDevice {
    pub fn vendor_id(&self) -> u16 {
        u16::from_le(self.dev_desc.id_vendor)
    }

    pub fn product_id(&self) -> u16 {
        u16::from_le(self.dev_desc.id_product)
    }

    pub fn device_class(&self) -> u8 {
        self.dev_desc.b_device_class
    }

    pub fn device_subclass(&self) -> u8 {
        self.dev_desc.b_device_sub_class
    }

    pub fn device_protocol(&self) -> u8 {
        self.dev_desc.b_device_protocol
    }

    pub fn usb_version(&self) -> u16 {
        u16::from_le(self.dev_desc.bcd_usb)
    }

    pub fn device_version(&self) -> u16 {
        u16::from_le(self.dev_desc.bcd_device)
    }

    pub fn max_packet_size0(&self) -> u8 {
        self.dev_desc.b_max_packet_size0
    }

    pub fn manufacturer(&self) -> Option<&str> {
        self.strings.manufacturer.as_deref()
    }

    pub fn product(&self) -> Option<&str> {
        self.strings.product.as_deref()
    }

    pub fn serial(&self) -> Option<&str> {
        self.strings.serial.as_deref()
    }

    pub fn display_name(&self) -> &str {
        self.strings.display_name().unwrap_or("Unknown Device")
    }

    pub fn is_hid(&self) -> bool {
        if self.dev_desc.b_device_class == CLASS_HID {
            return true;
        }
        if let Some(config) = &self.active_config {
            return config.interfaces.iter().any(|i| i.iface.is_hid());
        }
        false
    }

    pub fn is_mass_storage(&self) -> bool {
        if self.dev_desc.b_device_class == CLASS_MASS_STORAGE {
            return true;
        }
        if let Some(config) = &self.active_config {
            return config.interfaces.iter().any(|i| i.iface.is_mass_storage());
        }
        false
    }

    pub fn is_hub(&self) -> bool {
        self.dev_desc.b_device_class == CLASS_HUB
    }

    pub fn is_audio(&self) -> bool {
        if self.dev_desc.b_device_class == CLASS_AUDIO {
            return true;
        }
        if let Some(config) = &self.active_config {
            return config.interfaces.iter().any(|i| i.iface.is_audio());
        }
        false
    }

    pub fn find_interface(&self, class: u8) -> Option<&UsbInterfaceInfo> {
        self.active_config.as_ref()?.find_interface_by_class(class)
    }

    pub fn hid_interface(&self) -> Option<&UsbInterfaceInfo> {
        self.find_interface(CLASS_HID)
    }

    pub fn mass_storage_interface(&self) -> Option<&UsbInterfaceInfo> {
        self.find_interface(CLASS_MASS_STORAGE)
    }

    pub fn num_interfaces(&self) -> usize {
        self.active_config.as_ref()
            .map(|c| c.interfaces.len())
            .unwrap_or(0)
    }

    pub fn matches_vid_pid(&self, vid: u16, pid: u16) -> bool {
        self.vendor_id() == vid && self.product_id() == pid
    }

    pub fn is_high_speed(&self) -> bool {
        self.dev_desc.is_high_speed_capable()
    }

    pub fn is_super_speed(&self) -> bool {
        self.dev_desc.is_super_speed_capable()
    }

    pub fn class_name(&self) -> &'static str {
        self.dev_desc.class_name()
    }

    pub fn usb_version_string(&self) -> &'static str {
        self.dev_desc.usb_version_string()
    }
}
