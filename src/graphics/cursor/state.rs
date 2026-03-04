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

use core::sync::atomic::{AtomicI32, AtomicBool, Ordering};
use super::bitmap::{CURSOR_WIDTH, CURSOR_HEIGHT};

const CURSOR_PIXELS: usize = (CURSOR_WIDTH * CURSOR_HEIGHT) as usize;

// SAFETY: Single-threaded cursor state access
pub(super) static mut SAVED_PIXELS: [u32; CURSOR_PIXELS] = [0u32; CURSOR_PIXELS];
pub(super) static SAVED_X: AtomicI32 = AtomicI32::new(-1);
pub(super) static SAVED_Y: AtomicI32 = AtomicI32::new(-1);
pub(super) static CURSOR_VISIBLE: AtomicBool = AtomicBool::new(false);

pub(super) fn get_saved_position() -> (i32, i32) {
    (SAVED_X.load(Ordering::Relaxed), SAVED_Y.load(Ordering::Relaxed))
}

pub(super) fn set_saved_position(x: i32, y: i32) {
    SAVED_X.store(x, Ordering::Relaxed);
    SAVED_Y.store(y, Ordering::Relaxed);
}

pub(super) fn clear_saved_position() {
    SAVED_X.store(-1, Ordering::Relaxed);
    SAVED_Y.store(-1, Ordering::Relaxed);
}

pub(super) fn is_visible() -> bool {
    CURSOR_VISIBLE.load(Ordering::Relaxed)
}

pub(super) fn set_visible(visible: bool) {
    CURSOR_VISIBLE.store(visible, Ordering::Relaxed);
}
