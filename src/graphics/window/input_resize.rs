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
use super::state::{
    WINDOWS, RESIZE_BORDER, MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT, ResizeEdge,
};

pub(super) fn detect_resize_edge(x: i32, y: i32, w: i32, h: i32, mx: i32, my: i32) -> ResizeEdge {
    let border = RESIZE_BORDER;
    let right = x + w;
    let bottom = y + h;

    let on_left = mx >= x - border && mx < x + border;
    let on_right = mx > right - border && mx <= right + border;
    let on_top = my >= y - border && my < y + border;
    let on_bottom = my > bottom - border && my <= bottom + border;

    if on_top && on_left {
        ResizeEdge::TopLeft
    } else if on_top && on_right {
        ResizeEdge::TopRight
    } else if on_bottom && on_left {
        ResizeEdge::BottomLeft
    } else if on_bottom && on_right {
        ResizeEdge::BottomRight
    } else if on_top {
        ResizeEdge::Top
    } else if on_bottom {
        ResizeEdge::Bottom
    } else if on_left {
        ResizeEdge::Left
    } else if on_right {
        ResizeEdge::Right
    } else {
        ResizeEdge::None
    }
}

pub(super) fn handle_resize(idx: usize, mx: i32, my: i32, screen_w: u32, screen_h: u32) {
    let edge = ResizeEdge::from_u8(WINDOWS[idx].resize_edge.load(Ordering::Relaxed));
    let start_mx = WINDOWS[idx].drag_offset_x.load(Ordering::Relaxed);
    let start_my = WINDOWS[idx].drag_offset_y.load(Ordering::Relaxed);
    let start_x = WINDOWS[idx].resize_start_x.load(Ordering::Relaxed);
    let start_y = WINDOWS[idx].resize_start_y.load(Ordering::Relaxed);
    let start_w = WINDOWS[idx].resize_start_w.load(Ordering::Relaxed) as i32;
    let start_h = WINDOWS[idx].resize_start_h.load(Ordering::Relaxed) as i32;

    let dx = mx - start_mx;
    let dy = my - start_my;

    let min_w = MIN_WINDOW_WIDTH as i32;
    let min_h = MIN_WINDOW_HEIGHT as i32;
    let max_w = screen_w as i32 - 100;
    let max_h = screen_h as i32 - 80;

    let (new_x, new_y, new_w, new_h) = match edge {
        ResizeEdge::Right => {
            let w = (start_w + dx).clamp(min_w, max_w);
            (start_x, start_y, w, start_h)
        }
        ResizeEdge::Bottom => {
            let h = (start_h + dy).clamp(min_h, max_h);
            (start_x, start_y, start_w, h)
        }
        ResizeEdge::Left => {
            let w = (start_w - dx).clamp(min_w, max_w);
            let x = start_x + (start_w - w);
            (x, start_y, w, start_h)
        }
        ResizeEdge::Top => {
            let h = (start_h - dy).clamp(min_h, max_h);
            let y = start_y + (start_h - h);
            (start_x, y, start_w, h)
        }
        ResizeEdge::BottomRight => {
            let w = (start_w + dx).clamp(min_w, max_w);
            let h = (start_h + dy).clamp(min_h, max_h);
            (start_x, start_y, w, h)
        }
        ResizeEdge::BottomLeft => {
            let w = (start_w - dx).clamp(min_w, max_w);
            let h = (start_h + dy).clamp(min_h, max_h);
            let x = start_x + (start_w - w);
            (x, start_y, w, h)
        }
        ResizeEdge::TopRight => {
            let w = (start_w + dx).clamp(min_w, max_w);
            let h = (start_h - dy).clamp(min_h, max_h);
            let y = start_y + (start_h - h);
            (start_x, y, w, h)
        }
        ResizeEdge::TopLeft => {
            let w = (start_w - dx).clamp(min_w, max_w);
            let h = (start_h - dy).clamp(min_h, max_h);
            let x = start_x + (start_w - w);
            let y = start_y + (start_h - h);
            (x, y, w, h)
        }
        ResizeEdge::None => return,
    };

    WINDOWS[idx].x.store(new_x, Ordering::Relaxed);
    WINDOWS[idx].y.store(new_y, Ordering::Relaxed);
    WINDOWS[idx].width.store(new_w as u32, Ordering::Relaxed);
    WINDOWS[idx].height.store(new_h as u32, Ordering::Relaxed);
}
