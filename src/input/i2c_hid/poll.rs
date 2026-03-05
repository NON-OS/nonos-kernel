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

use super::device::HidDeviceType;
use super::state::{self, DEVICES};

pub fn poll() -> bool {
    if !state::is_available() {
        return false;
    }

    let mut devices = DEVICES.lock();

    if devices.is_empty() {
        return false;
    }

    let mut cursor_moved = false;

    for device in devices.iter_mut() {
        if !matches!(device.device_type(), HidDeviceType::Touchpad | HidDeviceType::Mouse) {
            continue;
        }

        match device.poll_touchpad() {
            Ok(Some(touchpad_state)) => {
                if touchpad_state.contact_count > 0 {
                    let dx = touchpad_state.delta_x;
                    let dy = touchpad_state.delta_y;

                    if dx != 0 || dy != 0 {
                        state::move_cursor(dx, dy);
                        state::record_update();
                        cursor_moved = true;
                    }
                }
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }

    cursor_moved
}

#[inline]
pub fn get_position() -> (i32, i32) {
    state::get_cursor()
}

#[inline]
pub fn set_screen_bounds(width: u32, height: u32) {
    state::set_screen_size(width, height);
}
