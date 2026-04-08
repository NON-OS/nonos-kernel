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

use super::device::HidDeviceState;
use super::error::{UsbHidError, UsbHidResult};
use super::state::{is_initialized, DEVICES};
use super::types::LedState;

pub fn set_leds(leds: LedState) -> UsbHidResult<()> {
    if !is_initialized() { return Err(UsbHidError::NotInitialized); }
    let mut devices = DEVICES.lock();
    let mut found_keyboard = false;
    for dev in devices.iter_mut() {
        if !dev.active || !dev.device_type.is_keyboard() { continue; }
        found_keyboard = true;
        if send_led_report(dev, leds).is_ok() { dev.leds = leds; }
    }
    if !found_keyboard { return Err(UsbHidError::DeviceNotFound); }
    Ok(())
}

pub fn get_leds() -> LedState {
    let devices = DEVICES.lock();
    for dev in devices.iter() {
        if dev.active && dev.device_type.is_keyboard() { return dev.leds; }
    }
    LedState::new()
}

fn send_led_report(dev: &HidDeviceState, leds: LedState) -> UsbHidResult<()> {
    let mut report = [leds.to_byte()];
    let setup_packet: [u8; 8] = [
        0x21, 0x09, 0x00, 0x02, dev.interface, 0x00, 0x01, 0x00,
    ];
    crate::drivers::xhci::control_transfer(dev.slot_id, setup_packet, Some(&mut report), 1_000_000)
        .map(|_| ())
        .map_err(|_| UsbHidError::SetLedFailed)
}
