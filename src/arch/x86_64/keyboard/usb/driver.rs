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
use super::enumeration::enumerate_devices;
use super::error::{UsbHidError, UsbHidResult};
use super::keyboard::poll_keyboard;
use super::mouse::poll_mouse;
use super::state::{is_initialized, DEVICES, DEVICE_COUNT, INITIALIZED, STATS};
use super::types::{HidDeviceInfo, HidDeviceType, MAX_HID_DEVICES};

pub fn init() -> UsbHidResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(UsbHidError::AlreadyInitialized);
    }

    if crate::drivers::xhci::init_xhci().is_err() {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(UsbHidError::XhciInitFailed);
    }

    if crate::drivers::usb::init_usb().is_err() {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(UsbHidError::UsbInitFailed);
    }

    enumerate_devices()?;

    Ok(())
}

pub fn shutdown() -> UsbHidResult<()> {
    if !is_initialized() {
        return Err(UsbHidError::NotInitialized);
    }

    let mut devices = DEVICES.lock();
    for dev in devices.iter_mut() {
        if dev.active {
            STATS.write().devices_disconnected += 1;
        }
        *dev = HidDeviceState::new();
    }

    DEVICE_COUNT.store(0, Ordering::Release);
    INITIALIZED.store(false, Ordering::SeqCst);

    Ok(())
}

pub fn poll() -> UsbHidResult<()> {
    if !is_initialized() {
        return Err(UsbHidError::NotInitialized);
    }

    STATS.write().poll_cycles += 1;

    let mut devices = DEVICES.lock();

    for dev in devices.iter_mut() {
        if !dev.active {
            continue;
        }

        match dev.device_type {
            HidDeviceType::BootKeyboard | HidDeviceType::ReportKeyboard => {
                poll_keyboard(dev, &STATS);
            }
            HidDeviceType::BootMouse | HidDeviceType::ScrollMouse | HidDeviceType::ExtendedMouse => {
                poll_mouse(dev, &STATS);
            }
            _ => {}
        }
    }

    Ok(())
}

pub fn get_device_info(index: usize) -> Option<HidDeviceInfo> {
    if index >= MAX_HID_DEVICES {
        return None;
    }

    let devices = DEVICES.lock();
    let dev = &devices[index];

    if !dev.active {
        return None;
    }

    Some(HidDeviceInfo {
        slot_id: dev.slot_id,
        device_type: dev.device_type,
        report_count: dev.report_count,
        error_count: dev.error_count,
    })
}
