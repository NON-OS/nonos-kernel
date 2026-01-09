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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use super::constants::*;

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

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EndpointDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub b_endpoint_address: u8,
    pub bm_attributes: u8,
    pub w_max_packet_size: u16,
    pub b_interval: u8,
}

impl EndpointDescriptor {
    pub fn endpoint_number(&self) -> u8 {
        self.b_endpoint_address & 0x0F
    }

    pub fn is_in(&self) -> bool {
        (self.b_endpoint_address & 0x80) != 0
    }

    pub fn is_out(&self) -> bool {
        (self.b_endpoint_address & 0x80) == 0
    }

    pub fn transfer_type(&self) -> u8 {
        self.bm_attributes & EP_TRANSFER_TYPE_MASK
    }

    pub fn is_control(&self) -> bool {
        self.transfer_type() == EP_TYPE_CONTROL
    }

    pub fn is_isochronous(&self) -> bool {
        self.transfer_type() == EP_TYPE_ISOCHRONOUS
    }

    pub fn is_bulk(&self) -> bool {
        self.transfer_type() == EP_TYPE_BULK
    }

    pub fn is_interrupt(&self) -> bool {
        self.transfer_type() == EP_TYPE_INTERRUPT
    }

    pub fn max_packet_size(&self) -> u16 {
        u16::from_le(self.w_max_packet_size) & 0x07FF
    }

    pub fn transfer_type_name(&self) -> &'static str {
        match self.transfer_type() {
            EP_TYPE_CONTROL => "Control",
            EP_TYPE_ISOCHRONOUS => "Isochronous",
            EP_TYPE_BULK => "Bulk",
            EP_TYPE_INTERRUPT => "Interrupt",
            _ => "Unknown",
        }
    }
}

#[derive(Clone, Default)]
pub struct UsbStringTable {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
}

impl UsbStringTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn display_name(&self) -> Option<&str> {
        self.product.as_deref().or(self.manufacturer.as_deref())
    }
}

#[derive(Clone)]
pub struct UsbInterfaceInfo {
    pub iface: InterfaceDescriptor,
    pub endpoints: Vec<EndpointDescriptor>,
}

impl UsbInterfaceInfo {
    pub fn find_in_endpoint(&self, transfer_type: u8) -> Option<&EndpointDescriptor> {
        self.endpoints.iter().find(|ep| {
            ep.is_in() && ep.transfer_type() == transfer_type
        })
    }

    pub fn find_out_endpoint(&self, transfer_type: u8) -> Option<&EndpointDescriptor> {
        self.endpoints.iter().find(|ep| {
            ep.is_out() && ep.transfer_type() == transfer_type
        })
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
        self.interfaces.iter().find(|iface| {
            iface.iface.b_interface_class == class
        })
    }

    pub fn find_hid_interface(&self) -> Option<&UsbInterfaceInfo> {
        self.find_interface_by_class(CLASS_HID)
    }

    pub fn find_mass_storage_interface(&self) -> Option<&UsbInterfaceInfo> {
        self.find_interface_by_class(CLASS_MASS_STORAGE)
    }
}

pub fn parse_interfaces(cfg: &[u8]) -> Result<Vec<UsbInterfaceInfo>, &'static str> {
    let mut i = 0usize;
    let total = cfg.len();

    if total < core::mem::size_of::<ConfigDescriptorHeader>() {
        return Err("Configuration descriptor too small");
    }
    i += core::mem::size_of::<ConfigDescriptorHeader>();

    let mut out = Vec::new();
    let mut cur_iface: Option<UsbInterfaceInfo> = None;

    while i + 1 < total {
        let len = cfg[i] as usize;
        if len == 0 || i + len > total {
            break;
        }
        let dtype = cfg[i + 1];

        match dtype {
            DT_INTERFACE => {
                if let Some(iface) = cur_iface.take() {
                    out.push(iface);
                }

                if i + core::mem::size_of::<InterfaceDescriptor>() <= total {
                    // SAFETY: bounds verified, using read_unaligned for packed struct.
                    let desc: InterfaceDescriptor = unsafe {
                        core::ptr::read_unaligned(cfg[i..].as_ptr() as *const _)
                    };
                    cur_iface = Some(UsbInterfaceInfo {
                        iface: desc,
                        endpoints: Vec::new(),
                    });
                }
            }
            DT_ENDPOINT => {
                if i + core::mem::size_of::<EndpointDescriptor>() <= total {
                    // SAFETY: bounds verified, using read_unaligned for packed struct.
                    let ep: EndpointDescriptor = unsafe {
                        core::ptr::read_unaligned(cfg[i..].as_ptr() as *const _)
                    };
                    if let Some(ref mut iface) = cur_iface {
                        iface.endpoints.push(ep);
                    }
                }
            }
            _ => {}
        }
        i += len;
    }

    if let Some(iface) = cur_iface.take() {
        out.push(iface);
    }

    Ok(out)
}
