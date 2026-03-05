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

use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, AtomicBool, Ordering};

pub(super) static MOUSE_X: AtomicI32 = AtomicI32::new(400);
pub(super) static MOUSE_Y: AtomicI32 = AtomicI32::new(300);
pub(super) static MOUSE_BUTTONS: AtomicU8 = AtomicU8::new(0);

pub(super) static SCREEN_WIDTH: AtomicI32 = AtomicI32::new(800);
pub(super) static SCREEN_HEIGHT: AtomicI32 = AtomicI32::new(600);

pub(super) static PACKET_BYTE0: AtomicU8 = AtomicU8::new(0);
pub(super) static PACKET_BYTE1: AtomicU8 = AtomicU8::new(0);
pub(super) static PACKET_BYTE2: AtomicU8 = AtomicU8::new(0);
pub(super) static PACKET_BYTE3: AtomicU8 = AtomicU8::new(0);
pub(super) static PACKET_INDEX: AtomicUsize = AtomicUsize::new(0);

pub(super) static MOUSE_AVAILABLE: AtomicBool = AtomicBool::new(false);
pub(super) static SCROLL_WHEEL_AVAILABLE: AtomicBool = AtomicBool::new(false);
pub(super) static SCROLL_DELTA: AtomicI32 = AtomicI32::new(0);

/// Flag set by interrupt handler when mouse state was updated
pub(super) static MOUSE_UPDATED: AtomicBool = AtomicBool::new(false);

/// Set screen dimensions for mouse bounds
pub(crate) fn set_screen_bounds(width: u32, height: u32) {
    SCREEN_WIDTH.store(width as i32, Ordering::SeqCst);
    SCREEN_HEIGHT.store(height as i32, Ordering::SeqCst);
    MOUSE_X.store((width / 2) as i32, Ordering::SeqCst);
    MOUSE_Y.store((height / 2) as i32, Ordering::SeqCst);
}

/// Get current mouse position
pub(crate) fn position() -> (i32, i32) {
    (MOUSE_X.load(Ordering::Relaxed), MOUSE_Y.load(Ordering::Relaxed))
}

/// Check if left button is pressed
pub(crate) fn left_pressed() -> bool {
    MOUSE_BUTTONS.load(Ordering::Relaxed) & 0x01 != 0
}

/// Check if right button is pressed
pub(crate) fn right_pressed() -> bool {
    MOUSE_BUTTONS.load(Ordering::Relaxed) & 0x02 != 0
}

/// Check if middle button is pressed
pub fn middle_pressed() -> bool {
    MOUSE_BUTTONS.load(Ordering::Relaxed) & 0x04 != 0
}

/// Get all button states as bitmask (bit0=left, bit1=right, bit2=middle)
pub fn buttons() -> u8 {
    MOUSE_BUTTONS.load(Ordering::Relaxed)
}

/// Get and clear scroll delta since last call
pub fn take_scroll_delta() -> i32 {
    SCROLL_DELTA.swap(0, Ordering::Relaxed)
}

/// Get current scroll delta (without clearing)
pub fn scroll_delta() -> i32 {
    SCROLL_DELTA.load(Ordering::Relaxed)
}

/// Check if scroll wheel is available
pub fn has_scroll_wheel() -> bool {
    SCROLL_WHEEL_AVAILABLE.load(Ordering::Relaxed)
}

/// Check if PS/2 mouse is available
pub fn is_available() -> bool {
    MOUSE_AVAILABLE.load(Ordering::Relaxed)
}
