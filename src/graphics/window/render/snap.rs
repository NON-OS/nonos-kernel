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

use crate::graphics::framebuffer::{dimensions, fill_rect};
use crate::graphics::window::state::{SnapZone, FOCUSED_WINDOW, MAX_WINDOWS, WINDOWS};
use core::sync::atomic::Ordering;

pub(super) fn draw_snap_preview() {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return;
    }
    if !WINDOWS[focused].dragging.load(Ordering::Relaxed) {
        return;
    }
    let pending = SnapZone::from_u8(WINDOWS[focused].pending_snap.load(Ordering::Relaxed));
    if pending == SnapZone::None {
        return;
    }
    let (screen_w, screen_h) = dimensions();
    let taskbar_height = 40u32;
    let menu_bar_height = 32u32;
    let usable_height = screen_h - taskbar_height - menu_bar_height;
    let half_width = screen_w / 2;
    let half_height = usable_height / 2;
    let (px, py, pw, ph) = match pending {
        SnapZone::Left => (0, menu_bar_height, half_width, usable_height),
        SnapZone::Right => (half_width, menu_bar_height, half_width, usable_height),
        SnapZone::Top => (0, menu_bar_height, screen_w, usable_height),
        SnapZone::TopLeft => (0, menu_bar_height, half_width, half_height),
        SnapZone::TopRight => (half_width, menu_bar_height, half_width, half_height),
        SnapZone::BottomLeft => (0, menu_bar_height + half_height, half_width, half_height),
        SnapZone::BottomRight => {
            (half_width, menu_bar_height + half_height, half_width, half_height)
        }
        SnapZone::None => return,
    };
    fill_rect(px, py, pw, ph, 0x2000D4FF);
    fill_rect(px, py, pw, 2, 0xFF00D4FF);
    fill_rect(px, py + ph - 2, pw, 2, 0xFF00D4FF);
    fill_rect(px, py, 2, ph, 0xFF00D4FF);
    fill_rect(px + pw - 2, py, 2, ph, 0xFF00D4FF);
}
