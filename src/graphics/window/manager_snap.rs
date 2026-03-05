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
use crate::graphics::framebuffer::dimensions;
use super::state::{WINDOWS, FOCUSED_WINDOW, MAX_WINDOWS, SnapZone};
use super::scroll;
use super::manager::minimize;

pub fn snap_focused(zone: SnapZone) {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS || !WINDOWS[focused].active.load(Ordering::Relaxed) {
        return;
    }

    if WINDOWS[focused].minimized.load(Ordering::Relaxed) {
        return;
    }

    let (screen_w, screen_h) = dimensions();
    apply_snap_zone(focused, zone, screen_w, screen_h);
}

pub fn snap_left() {
    snap_focused(SnapZone::Left);
}

pub fn snap_right() {
    snap_focused(SnapZone::Right);
}

pub fn snap_top() {
    snap_focused(SnapZone::Top);
}

pub fn unsnap_focused() {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS || !WINDOWS[focused].active.load(Ordering::Relaxed) {
        return;
    }

    if !WINDOWS[focused].snapped.load(Ordering::Relaxed) {
        minimize(focused);
        return;
    }

    let pre_x = WINDOWS[focused].pre_snap_x.load(Ordering::Relaxed);
    let pre_y = WINDOWS[focused].pre_snap_y.load(Ordering::Relaxed);
    let pre_w = WINDOWS[focused].pre_snap_w.load(Ordering::Relaxed);
    let pre_h = WINDOWS[focused].pre_snap_h.load(Ordering::Relaxed);

    WINDOWS[focused].x.store(pre_x, Ordering::Relaxed);
    WINDOWS[focused].y.store(pre_y, Ordering::Relaxed);
    WINDOWS[focused].width.store(pre_w, Ordering::Relaxed);
    WINDOWS[focused].height.store(pre_h, Ordering::Relaxed);
    WINDOWS[focused].snapped.store(false, Ordering::Relaxed);
    WINDOWS[focused].snap_zone.store(0, Ordering::Relaxed);
    WINDOWS[focused].maximized.store(false, Ordering::Relaxed);
}

fn apply_snap_zone(idx: usize, zone: SnapZone, screen_w: u32, screen_h: u32) {
    const DOCK_WIDTH: u32 = 60;
    const MENUBAR_HEIGHT: u32 = 32;
    const TASKBAR_HEIGHT: u32 = 40;

    let usable_w = screen_w - DOCK_WIDTH;
    let usable_h = screen_h - MENUBAR_HEIGHT - TASKBAR_HEIGHT;
    let half_w = usable_w / 2;
    let half_h = usable_h / 2;

    if !WINDOWS[idx].snapped.load(Ordering::Relaxed) {
        WINDOWS[idx].pre_snap_x.store(WINDOWS[idx].x.load(Ordering::Relaxed), Ordering::Relaxed);
        WINDOWS[idx].pre_snap_y.store(WINDOWS[idx].y.load(Ordering::Relaxed), Ordering::Relaxed);
        WINDOWS[idx].pre_snap_w.store(WINDOWS[idx].width.load(Ordering::Relaxed), Ordering::Relaxed);
        WINDOWS[idx].pre_snap_h.store(WINDOWS[idx].height.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    let (x, y, w, h) = match zone {
        SnapZone::Left => (DOCK_WIDTH as i32, MENUBAR_HEIGHT as i32, half_w, usable_h),
        SnapZone::Right => ((DOCK_WIDTH + half_w) as i32, MENUBAR_HEIGHT as i32, half_w, usable_h),
        SnapZone::Top => (DOCK_WIDTH as i32, MENUBAR_HEIGHT as i32, usable_w, usable_h),
        SnapZone::TopLeft => (DOCK_WIDTH as i32, MENUBAR_HEIGHT as i32, half_w, half_h),
        SnapZone::TopRight => ((DOCK_WIDTH + half_w) as i32, MENUBAR_HEIGHT as i32, half_w, half_h),
        SnapZone::BottomLeft => (DOCK_WIDTH as i32, (MENUBAR_HEIGHT + half_h) as i32, half_w, half_h),
        SnapZone::BottomRight => ((DOCK_WIDTH + half_w) as i32, (MENUBAR_HEIGHT + half_h) as i32, half_w, half_h),
        SnapZone::None => return,
    };

    WINDOWS[idx].x.store(x, Ordering::Relaxed);
    WINDOWS[idx].y.store(y, Ordering::Relaxed);
    WINDOWS[idx].width.store(w, Ordering::Relaxed);
    WINDOWS[idx].height.store(h, Ordering::Relaxed);
    WINDOWS[idx].snapped.store(true, Ordering::Relaxed);
    WINDOWS[idx].snap_zone.store(zone as u8, Ordering::Relaxed);
    WINDOWS[idx].maximized.store(zone == SnapZone::Top, Ordering::Relaxed);

    scroll::reset(idx);
}
