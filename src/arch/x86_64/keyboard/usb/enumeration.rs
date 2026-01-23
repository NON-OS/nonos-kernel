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

use core::sync::atomic::Ordering;

use super::device::HidDeviceState;
use super::error::{UsbHidError, UsbHidResult};
use super::state::{is_initialized, DEVICES, DEVICE_COUNT, STATS};
use super::types::{
    HidDeviceType, LedState, ModifierState, MouseButtonState,
    HID_CLASS, HID_PROTOCOL_KEYBOARD, HID_PROTOCOL_MOUSE, HID_SUBCLASS_BOOT,
    KEYBOARD_REPORT_SIZE,
};

pub fn enumerate_devices() -> UsbHidResult<()> {
    if !is_initialized() {
        return Err(UsbHidError::NotInitialized);
    }

    let usb_mgr = match crate::drivers::usb::get_manager() {
        Some(mgr) => mgr,
        None => return Err(UsbHidError::UsbInitFailed),
    };

    let mut devices = DEVICES.lock();
    let mut device_count = 0u8;

    for dev in devices.iter_mut() {
        dev.active = false;
    }

    for usb_dev in usb_mgr.devices() {
        if let Some(cfg) = &usb_dev.active_config {
            for iface in &cfg.interfaces {
                if let Some(new_dev) = try_create_hid_device(usb_dev, iface) {
                    if let Some(slot) = find_free_slot(&devices) {
                        devices[slot] = new_dev;
                        device_count += 1;
                        STATS.write().devices_connected += 1;
                    }
                }
            }
        }
    }

    DEVICE_COUNT.store(device_count, Ordering::Release);

    if device_count == 0 {
        return Err(UsbHidError::NoDevices);
    }

    Ok(())
}

fn try_create_hid_device(
    usb_dev: &crate::drivers::usb::UsbDevice,
    iface: &crate::drivers::usb::UsbInterface,
) -> Option<HidDeviceState> {
    let class = iface.iface.b_interface_class;
    let subclass = iface.iface.b_interface_sub_class;
    let protocol = iface.iface.b_interface_protocol;

    if class != HID_CLASS {
        return None;
    }

    let endpoint = iface.endpoints.iter()
        .find(|ep| (ep.b_endpoint_address & 0x80) != 0)
        .map(|ep| ep.b_endpoint_address)?;

    let device_type = classify_device(subclass, protocol);

    if subclass == HID_SUBCLASS_BOOT {
        let _ = set_boot_protocol(usb_dev.slot_id, iface.iface.b_interface_number);
    }

    Some(HidDeviceState {
        slot_id: usb_dev.slot_id,
        endpoint,
        device_type,
        interface: iface.iface.b_interface_number,
        active: true,
        last_keyboard_report: [0; KEYBOARD_REPORT_SIZE],
        modifiers: ModifierState::from_byte(0),
        leds: LedState::new(),
        last_mouse_buttons: MouseButtonState::from_byte(0),
        report_count: 0,
        error_count: 0,
    })
}

fn classify_device(subclass: u8, protocol: u8) -> HidDeviceType {
    if subclass == HID_SUBCLASS_BOOT {
        match protocol {
            HID_PROTOCOL_KEYBOARD => HidDeviceType::BootKeyboard,
            HID_PROTOCOL_MOUSE => HidDeviceType::BootMouse,
            _ => HidDeviceType::Unknown,
        }
    } else {
        match protocol {
            HID_PROTOCOL_KEYBOARD => HidDeviceType::ReportKeyboard,
            HID_PROTOCOL_MOUSE => HidDeviceType::ScrollMouse,
            _ => HidDeviceType::Unknown,
        }
    }
}

fn find_free_slot(devices: &[HidDeviceState]) -> Option<usize> {
    devices.iter()
        .enumerate()
        .find(|(_, d)| !d.active)
        .map(|(i, _)| i)
}

fn set_boot_protocol(slot_id: u8, interface: u8) -> UsbHidResult<()> {
    let setup_packet: [u8; 8] = [
        0x21,       // bmRequestType: class, interface, host-to-device
        0x0B,       // bRequest: SET_PROTOCOL
        0x00, 0x00, // wValue: boot protocol (0)
        interface, 0x00,
        0x00, 0x00, // wLength: 0
    ];

    crate::drivers::xhci::control_transfer(slot_id, setup_packet, None, 1_000_000)
        .map(|_| ())
        .map_err(|_| UsbHidError::SetProtocolFailed)
}
