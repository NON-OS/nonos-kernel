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

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

pub(crate) static USB_INIT: AtomicBool = AtomicBool::new(false);
pub(crate) static KBD_AVAIL: AtomicBool = AtomicBool::new(false);
pub(crate) static MOUSE_AVAIL: AtomicBool = AtomicBool::new(false);
pub(crate) static TABLET_MODE: AtomicBool = AtomicBool::new(false);

pub(crate) static MOUSE_X: AtomicI32 = AtomicI32::new(400);
pub(crate) static MOUSE_Y: AtomicI32 = AtomicI32::new(300);
pub(crate) static MOUSE_BTN: AtomicU8 = AtomicU8::new(0);
pub(crate) static SCR_W: AtomicI32 = AtomicI32::new(800);
pub(crate) static SCR_H: AtomicI32 = AtomicI32::new(600);

pub fn set_screen_bounds(w: u32, h: u32) {
    SCR_W.store(w as i32, Ordering::SeqCst);
    SCR_H.store(h as i32, Ordering::SeqCst);
    MOUSE_X.store((w / 2) as i32, Ordering::SeqCst);
    MOUSE_Y.store((h / 2) as i32, Ordering::SeqCst);
}

pub fn is_available() -> bool {
    USB_INIT.load(Ordering::Relaxed)
}
pub fn keyboard_available() -> bool {
    KBD_AVAIL.load(Ordering::Relaxed)
}
pub fn mouse_available() -> bool {
    MOUSE_AVAIL.load(Ordering::Relaxed)
}

pub fn mouse_position() -> (i32, i32) {
    (MOUSE_X.load(Ordering::Relaxed), MOUSE_Y.load(Ordering::Relaxed))
}

pub fn left_pressed() -> bool {
    MOUSE_BTN.load(Ordering::Relaxed) & 0x01 != 0
}
pub fn right_pressed() -> bool {
    MOUSE_BTN.load(Ordering::Relaxed) & 0x02 != 0
}
