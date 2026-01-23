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
use super::types::{MouseButtonState, UsbHidStats};

const MOUSE_BUTTONS: [(fn(&MouseButtonState) -> bool, u8); 5] = [
    (|b| b.left, 0),
    (|b| b.right, 1),
    (|b| b.middle, 2),
    (|b| b.button4, 3),
    (|b| b.button5, 4),
];

pub fn poll_mouse(dev: &mut HidDeviceState, stats: &RwLock<UsbHidStats>) {
    let mut report = [0u8; 8];

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

    dev.report_count += 1;
    stats.write().mouse_reports += 1;

    let buttons = MouseButtonState::from_byte(report[0]);
    let dx = report[1] as i8 as i16;
    let dy = report[2] as i8 as i16;
    let dz = if dev.device_type.has_scroll() && report.len() > 3 {
        report[3] as i8
    } else {
        0
    };

    process_movement(dx, dy, dz, stats);
    process_button_changes(dev.last_mouse_buttons, buttons, stats);

    dev.last_mouse_buttons = buttons;
}

fn process_movement(dx: i16, dy: i16, dz: i8, stats: &RwLock<UsbHidStats>) {
    if dx != 0 || dy != 0 {
        let _ = push_event(InputEvent::mouse_move(dx, dy));
        stats.write().mouse_moves += 1;
    }

    if dz != 0 {
        let _ = push_event(InputEvent::mouse_scroll(dz));
    }
}

fn process_button_changes(
    old: MouseButtonState,
    new: MouseButtonState,
    stats: &RwLock<UsbHidStats>,
) {
    for (get_state, button_id) in MOUSE_BUTTONS {
        let old_state = get_state(&old);
        let new_state = get_state(&new);

        if old_state != new_state {
            let _ = push_event(InputEvent::mouse_button(button_id, new_state));
            stats.write().mouse_buttons += 1;
        }
    }
}
