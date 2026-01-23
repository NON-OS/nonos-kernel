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

use spin::RwLock;

use crate::arch::keyboard::input::{push_event, InputEvent};

use super::device::HidDeviceState;
use super::error::{UsbHidError, UsbHidResult};
use super::state::{is_initialized, DEVICES};
use super::types::{LedState, ModifierState, UsbHidStats, KEYBOARD_REPORT_SIZE};
use super::usage::{
    self, hid_to_scancode, KEY_LEFT_ALT, KEY_LEFT_CTRL, KEY_LEFT_GUI, KEY_LEFT_SHIFT,
    KEY_RIGHT_ALT, KEY_RIGHT_CTRL, KEY_RIGHT_GUI, KEY_RIGHT_SHIFT,
};

const MODIFIER_KEYS: [(fn(&ModifierState) -> bool, u8); 8] = [
    (|m| m.left_ctrl, KEY_LEFT_CTRL),
    (|m| m.left_shift, KEY_LEFT_SHIFT),
    (|m| m.left_alt, KEY_LEFT_ALT),
    (|m| m.left_gui, KEY_LEFT_GUI),
    (|m| m.right_ctrl, KEY_RIGHT_CTRL),
    (|m| m.right_shift, KEY_RIGHT_SHIFT),
    (|m| m.right_alt, KEY_RIGHT_ALT),
    (|m| m.right_gui, KEY_RIGHT_GUI),
];

pub fn poll_keyboard(dev: &mut HidDeviceState, stats: &RwLock<UsbHidStats>) {
    let mut report = [0u8; KEYBOARD_REPORT_SIZE];

    let result = crate::drivers::usb::poll_endpoint(
        dev.slot_id,
        dev.endpoint,
        &mut report,
    );

    if result.is_err() {
        dev.error_count += 1;
        stats.write().errors += 1;
        return;
    }

    if report == dev.last_keyboard_report {
        return;
    }

    dev.report_count += 1;
    stats.write().keyboard_reports += 1;

    let new_mods = ModifierState::from_byte(report[0]);
    process_modifier_changes(&dev.modifiers, &new_mods, stats);
    dev.modifiers = new_mods;

    process_key_changes(dev, &report, stats);
    dev.last_keyboard_report = report;
}

fn process_key_changes(
    dev: &HidDeviceState,
    report: &[u8; KEYBOARD_REPORT_SIZE],
    stats: &RwLock<UsbHidStats>,
) {
    let old_keys = &dev.last_keyboard_report[2..8];
    let new_keys = &report[2..8];

    // Released keys
    for &old_key in old_keys {
        if old_key != 0 && !new_keys.contains(&old_key) {
            let scancode = hid_to_scancode(old_key);
            if scancode != 0 {
                let _ = push_event(InputEvent::key_release(scancode));
                stats.write().key_releases += 1;
            }
        }
    }

    // Pressed keys
    for &new_key in new_keys {
        if new_key != 0 && !old_keys.contains(&new_key) {
            if new_key == usage::ERR_ROLLOVER {
                continue;
            }

            let scancode = hid_to_scancode(new_key);
            if scancode != 0 {
                let _ = push_event(InputEvent::key_press(scancode));
                stats.write().key_presses += 1;
            }
        }
    }
}

fn process_modifier_changes(
    old: &ModifierState,
    new: &ModifierState,
    stats: &RwLock<UsbHidStats>,
) {
    for (get_field, usage_code) in MODIFIER_KEYS {
        let old_state = get_field(old);
        let new_state = get_field(new);

        if old_state != new_state {
            let scancode = hid_to_scancode(usage_code);
            if new_state {
                let _ = push_event(InputEvent::key_press(scancode));
                stats.write().key_presses += 1;
            } else {
                let _ = push_event(InputEvent::key_release(scancode));
                stats.write().key_releases += 1;
            }
        }
    }
}

pub fn set_leds(leds: LedState) -> UsbHidResult<()> {
    if !is_initialized() {
        return Err(UsbHidError::NotInitialized);
    }

    let mut devices = DEVICES.lock();
    let mut found_keyboard = false;

    for dev in devices.iter_mut() {
        if !dev.active || !dev.device_type.is_keyboard() {
            continue;
        }

        found_keyboard = true;

        if send_led_report(dev, leds).is_ok() {
            dev.leds = leds;
        }
    }

    if !found_keyboard {
        return Err(UsbHidError::DeviceNotFound);
    }

    Ok(())
}

pub fn get_leds() -> LedState {
    let devices = DEVICES.lock();
    for dev in devices.iter() {
        if dev.active && dev.device_type.is_keyboard() {
            return dev.leds;
        }
    }
    LedState::new()
}

fn send_led_report(dev: &HidDeviceState, leds: LedState) -> UsbHidResult<()> {
    let mut report = [leds.to_byte()];
    let setup_packet: [u8; 8] = [
        0x21,       // bmRequestType: class, interface, host-to-device
        0x09,       // bRequest: SET_REPORT
        0x00, 0x02, // wValue: report type (output) | report ID (0)
        dev.interface, 0x00,
        0x01, 0x00, // wLength: 1
    ];

    crate::drivers::xhci::control_transfer(dev.slot_id, setup_packet, Some(&mut report), 1_000_000)
        .map(|_| ())
        .map_err(|_| UsbHidError::SetLedFailed)
}
