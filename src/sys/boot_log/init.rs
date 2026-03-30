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

use core::sync::atomic::Ordering;
use super::state::{DISPLAY_ENABLED, LOG_Y, MIN_LOG_Y};

pub fn init_after_fb(cursor_y: u32) {
    crate::sys::serial::print(b"[BOOTLOG] cursor_y=");
    crate::sys::serial::print_dec(cursor_y as u64);
    crate::sys::serial::println(b"");
    if let Ok(info) = crate::display::get_framebuffer() {
        let start_y = if cursor_y > 0 { cursor_y } else { 192 };
        let max_y = info.height.saturating_sub(100);
        let final_y = start_y.min(max_y);
        crate::sys::serial::print(b"[BOOTLOG] final_y=");
        crate::sys::serial::print_dec(final_y as u64);
        crate::sys::serial::println(b"");
        LOG_Y.store(final_y, Ordering::Relaxed);
        MIN_LOG_Y.store(final_y, Ordering::Relaxed);
        DISPLAY_ENABLED.store(true, Ordering::Release);
    } else {
        crate::sys::serial::println(b"[BOOTLOG] ERROR: no framebuffer!");
    }
}
