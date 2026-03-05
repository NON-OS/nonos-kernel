// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! I2C HID touchpad polling.
//!
//! This module handles polling touchpad devices for input and updating cursor position.

use super::device::HidDeviceType;
use super::state::{self, DEVICES};

/// Poll all touchpad devices for input.
///
/// Returns true if cursor position was updated, false otherwise.
pub fn poll() -> bool {
    // Check if I2C HID is available
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

/// Get current cursor position.
#[inline]
pub fn get_position() -> (i32, i32) {
    state::get_cursor()
}

/// Set screen bounds for cursor clamping.
#[inline]
pub fn set_screen_bounds(width: u32, height: u32) {
    state::set_screen_size(width, height);
}
