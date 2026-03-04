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
use super::state::{WINDOWS, SnapZone, SNAP_THRESHOLD};

pub(super) fn detect_snap_zone(mx: i32, my: i32, screen_w: u32, screen_h: u32) -> SnapZone {
    let sw = screen_w as i32;
    let sh = screen_h as i32;
    let taskbar_height = 40i32;

    let near_left = mx <= SNAP_THRESHOLD;
    let near_right = mx >= sw - SNAP_THRESHOLD;
    let near_top = my <= 32 + SNAP_THRESHOLD;
    let near_bottom = my >= sh - taskbar_height - SNAP_THRESHOLD;

    if near_left && near_top {
        return SnapZone::TopLeft;
    }
    if near_right && near_top {
        return SnapZone::TopRight;
    }
    if near_left && near_bottom {
        return SnapZone::BottomLeft;
    }
    if near_right && near_bottom {
        return SnapZone::BottomRight;
    }

    if near_top {
        return SnapZone::Top;
    }
    if near_left {
        return SnapZone::Left;
    }
    if near_right {
        return SnapZone::Right;
    }

    SnapZone::None
}

pub(super) fn apply_snap(idx: usize, zone: SnapZone, screen_w: u32, screen_h: u32) {
    let taskbar_height = 40u32;
    let menu_bar_height = 32u32;
    let usable_height = screen_h - taskbar_height - menu_bar_height;
    let half_width = screen_w / 2;
    let half_height = usable_height / 2;

    if !WINDOWS[idx].snapped.load(Ordering::Relaxed) {
        WINDOWS[idx].pre_snap_x.store(WINDOWS[idx].x.load(Ordering::Relaxed), Ordering::Relaxed);
        WINDOWS[idx].pre_snap_y.store(WINDOWS[idx].y.load(Ordering::Relaxed), Ordering::Relaxed);
        WINDOWS[idx].pre_snap_w.store(WINDOWS[idx].width.load(Ordering::Relaxed), Ordering::Relaxed);
        WINDOWS[idx].pre_snap_h.store(WINDOWS[idx].height.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    let (x, y, w, h) = match zone {
        SnapZone::Left => (0, menu_bar_height as i32, half_width, usable_height),
        SnapZone::Right => (half_width as i32, menu_bar_height as i32, half_width, usable_height),
        SnapZone::Top => (0, menu_bar_height as i32, screen_w, usable_height),
        SnapZone::TopLeft => (0, menu_bar_height as i32, half_width, half_height),
        SnapZone::TopRight => (half_width as i32, menu_bar_height as i32, half_width, half_height),
        SnapZone::BottomLeft => (0, (menu_bar_height + half_height) as i32, half_width, half_height),
        SnapZone::BottomRight => (half_width as i32, (menu_bar_height + half_height) as i32, half_width, half_height),
        SnapZone::None => return,
    };

    WINDOWS[idx].x.store(x, Ordering::Relaxed);
    WINDOWS[idx].y.store(y, Ordering::Relaxed);
    WINDOWS[idx].width.store(w, Ordering::Relaxed);
    WINDOWS[idx].height.store(h, Ordering::Relaxed);
    WINDOWS[idx].snapped.store(true, Ordering::Relaxed);
    WINDOWS[idx].snap_zone.store(zone as u8, Ordering::Relaxed);
    WINDOWS[idx].maximized.store(zone == SnapZone::Top, Ordering::Relaxed);
}

pub(super) fn restore_from_snap(idx: usize, mx: i32) {
    if !WINDOWS[idx].snapped.load(Ordering::Relaxed) {
        return;
    }

    let pre_x = WINDOWS[idx].pre_snap_x.load(Ordering::Relaxed);
    let pre_y = WINDOWS[idx].pre_snap_y.load(Ordering::Relaxed);
    let pre_w = WINDOWS[idx].pre_snap_w.load(Ordering::Relaxed);
    let pre_h = WINDOWS[idx].pre_snap_h.load(Ordering::Relaxed);

    let half_w = pre_w as i32 / 2;
    let centered_x = if (mx - pre_x).abs() < half_w { pre_x } else { mx - half_w };
    WINDOWS[idx].x.store(centered_x.max(60), Ordering::Relaxed);
    WINDOWS[idx].y.store(pre_y, Ordering::Relaxed);
    WINDOWS[idx].width.store(pre_w, Ordering::Relaxed);
    WINDOWS[idx].height.store(pre_h, Ordering::Relaxed);
    WINDOWS[idx].snapped.store(false, Ordering::Relaxed);
    WINDOWS[idx].snap_zone.store(0, Ordering::Relaxed);
    WINDOWS[idx].maximized.store(false, Ordering::Relaxed);

    WINDOWS[idx].drag_offset_x.store(pre_w as i32 / 2, Ordering::Relaxed);
}
