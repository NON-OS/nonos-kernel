// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

static MAGNIFICATION_ENABLED: AtomicBool = AtomicBool::new(true);
static HOVER_INDEX: AtomicU8 = AtomicU8::new(255);
static HOVER_X: AtomicI32 = AtomicI32::new(-1);
static HOVER_Y: AtomicI32 = AtomicI32::new(-1);

pub(super) fn is_magnification_enabled() -> bool {
    MAGNIFICATION_ENABLED.load(Ordering::Relaxed)
}

pub(super) fn set_magnification_enabled(enabled: bool) {
    MAGNIFICATION_ENABLED.store(enabled, Ordering::Relaxed);
}

pub(super) fn get_hover_index() -> Option<u8> {
    let idx = HOVER_INDEX.load(Ordering::Relaxed);
    if idx == 255 { None } else { Some(idx) }
}

pub(super) fn set_hover_index(idx: Option<u8>) {
    HOVER_INDEX.store(idx.unwrap_or(255), Ordering::Relaxed);
}

pub(super) fn get_hover_position() -> (i32, i32) {
    (HOVER_X.load(Ordering::Relaxed), HOVER_Y.load(Ordering::Relaxed))
}

pub(super) fn set_hover_position(x: i32, y: i32) {
    HOVER_X.store(x, Ordering::Relaxed);
    HOVER_Y.store(y, Ordering::Relaxed);
}

pub(super) fn clear_hover() {
    HOVER_INDEX.store(255, Ordering::Relaxed);
    HOVER_X.store(-1, Ordering::Relaxed);
    HOVER_Y.store(-1, Ordering::Relaxed);
}
