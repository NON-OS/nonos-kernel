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

use super::constants::*;
use super::keyboard::process_keyboard_report;
use super::mouse::process_mouse_report;
use crate::drivers::usb::class_driver::{interface_matches, register_class_driver, UsbClassDriver};
use crate::drivers::usb::constants::{CLASS_HID, DEFAULT_CONTROL_TIMEOUT_US, RT_INTF, TYPE_CLASS};
use crate::drivers::usb::descriptors::{UsbConfiguration, UsbInterfaceInfo};
use crate::drivers::usb::device::UsbDevice;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidDeviceType {
    Keyboard,
    Mouse,
    Generic,
}

#[derive(Clone)]
pub struct HidDevice {
    pub slot_id: u8,
    pub interface_num: u8,
    pub device_type: HidDeviceType,
    pub endpoint_addr: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

static HID_DEVICES: Mutex<Vec<HidDevice>> = Mutex::new(Vec::new());

pub(super) struct HidDriver;

impl UsbClassDriver for HidDriver {
    fn matches(&self, _dev: &UsbDevice, _cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> bool {
        interface_matches(iface, CLASS_HID, None, None)
    }

    fn bind(
        &self,
        dev: &UsbDevice,
        _cfg: &UsbConfiguration,
        iface: &UsbInterfaceInfo,
    ) -> Result<(), &'static str> {
        let protocol = iface.iface.b_interface_protocol;
        let device_type = match protocol {
            HID_PROTOCOL_KEYBOARD => HidDeviceType::Keyboard,
            HID_PROTOCOL_MOUSE => HidDeviceType::Mouse,
            _ => HidDeviceType::Generic,
        };
        let ep = iface
            .endpoints
            .iter()
            .find(|e| (e.b_endpoint_address & 0x80) != 0)
            .ok_or("No interrupt IN endpoint")?;
        let hid_device = HidDevice {
            slot_id: dev.slot_id,
            interface_num: iface.iface.b_interface_number,
            device_type,
            endpoint_addr: ep.b_endpoint_address,
            max_packet_size: ep.w_max_packet_size,
            interval: ep.b_interval,
        };
        set_boot_protocol(dev.slot_id, iface.iface.b_interface_number)?;
        set_idle(dev.slot_id, iface.iface.b_interface_number, 0, 0)?;
        let mut devices = HID_DEVICES.lock();
        if devices.len() < MAX_HID_DEVICES {
            devices.push(hid_device);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "hid"
    }
    fn priority(&self) -> u8 {
        50
    }
}

fn set_boot_protocol(slot_id: u8, interface: u8) -> Result<(), &'static str> {
    let setup =
        [TYPE_CLASS | RT_INTF, HID_REQ_SET_PROTOCOL, HID_BOOT_PROTOCOL, 0, interface, 0, 0, 0];
    crate::drivers::xhci::control_transfer(slot_id, setup, None, DEFAULT_CONTROL_TIMEOUT_US)?;
    Ok(())
}

fn set_idle(slot_id: u8, interface: u8, report_id: u8, duration: u8) -> Result<(), &'static str> {
    let setup = [TYPE_CLASS | RT_INTF, HID_REQ_SET_IDLE, report_id, duration, interface, 0, 0, 0];
    crate::drivers::xhci::control_transfer(slot_id, setup, None, DEFAULT_CONTROL_TIMEOUT_US)?;
    Ok(())
}

pub fn process_hid_report(slot_id: u8, interface: u8, report: &[u8]) {
    let devices = HID_DEVICES.lock();
    if let Some(device) =
        devices.iter().find(|d| d.slot_id == slot_id && d.interface_num == interface)
    {
        match device.device_type {
            HidDeviceType::Keyboard => {
                if report.len() >= BOOT_KEYBOARD_REPORT_SIZE {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&report[..8]);
                    process_keyboard_report(&buf);
                }
            }
            HidDeviceType::Mouse => {
                process_mouse_report(report);
            }
            HidDeviceType::Generic => {}
        }
    }
}

pub fn register() {
    register_class_driver(Arc::new(HidDriver));
}
pub fn device_count() -> usize {
    HID_DEVICES.lock().len()
}
pub fn get_devices() -> Vec<HidDevice> {
    HID_DEVICES.lock().clone()
}
