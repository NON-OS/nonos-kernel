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

use super::zones::{zone_rect, SnapZone};
use crate::graphics::framebuffer::fill_rounded_rect;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static PREVIEW_VISIBLE: AtomicBool = AtomicBool::new(false);
static PREVIEW_ZONE: AtomicU8 = AtomicU8::new(0);

const PREVIEW_BG: u32 = 0x4000D4FF;
const PREVIEW_BORDER: u32 = 0x8000D4FF;

pub fn show_preview(zone: SnapZone) {
    PREVIEW_ZONE.store(zone as u8, Ordering::Relaxed);
    PREVIEW_VISIBLE.store(true, Ordering::Relaxed);
}

pub fn hide_preview() {
    PREVIEW_VISIBLE.store(false, Ordering::Relaxed);
}

pub fn is_preview_visible() -> bool {
    PREVIEW_VISIBLE.load(Ordering::Relaxed)
}

pub fn get_preview_zone() -> SnapZone {
    let z = PREVIEW_ZONE.load(Ordering::Relaxed);
    match z {
        1 => SnapZone::Left,
        2 => SnapZone::Right,
        3 => SnapZone::Top,
        4 => SnapZone::TopLeft,
        5 => SnapZone::TopRight,
        6 => SnapZone::BottomLeft,
        7 => SnapZone::BottomRight,
        8 => SnapZone::LeftThird,
        9 => SnapZone::CenterThird,
        10 => SnapZone::RightThird,
        11 => SnapZone::LeftTwoThirds,
        12 => SnapZone::RightTwoThirds,
        _ => SnapZone::None,
    }
}

pub fn draw_snap_preview(fb: &mut [u32], pitch: usize, sw: u32, sh: u32) {
    if !is_preview_visible() {
        return;
    }
    let zone = get_preview_zone();
    if zone == SnapZone::None {
        return;
    }
    let (x, y, w, h) = zone_rect(zone, sw, sh);
    if w == 0 || h == 0 {
        return;
    }
    fill_rounded_rect(fb, pitch, x as u32, y as u32, w, h, 12, PREVIEW_BG);
    draw_border(fb, pitch, x as u32, y as u32, w, h, 2, PREVIEW_BORDER);
}

fn draw_border(
    fb: &mut [u32],
    pitch: usize,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    thick: u32,
    color: u32,
) {
    for t in 0..thick {
        for px in x..(x + w) {
            if (y + t) < h {
                fb[(y + t) as usize * pitch + px as usize] = color;
            }
            if (y + h - 1 - t) >= y {
                fb[(y + h - 1 - t) as usize * pitch + px as usize] = color;
            }
        }
        for py in y..(y + h) {
            if (x + t) < w {
                fb[py as usize * pitch + (x + t) as usize] = color;
            }
            if (x + w - 1 - t) >= x {
                fb[py as usize * pitch + (x + w - 1 - t) as usize] = color;
            }
        }
    }
}
