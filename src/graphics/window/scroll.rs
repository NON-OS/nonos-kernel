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
use crate::graphics::framebuffer::fill_rect;
use super::state::{WINDOWS, MAX_WINDOWS, SCROLLBAR_WIDTH, SCROLLBAR_MIN_THUMB, TITLE_BAR_HEIGHT};

const SCROLLBAR_BG: u32 = 0xFF21262D;
const SCROLLBAR_THUMB: u32 = 0xFF4A5568;
const SCROLLBAR_THUMB_HOVER: u32 = 0xFF6B7280;

fn calc_thumb(viewport_size: u32, content_size: u32, scroll_offset: i32) -> (u32, u32) {
    if content_size <= viewport_size {
        return (0, viewport_size);
    }

    let ratio = viewport_size as f32 / content_size as f32;
    let thumb_size = ((viewport_size as f32 * ratio) as u32).max(SCROLLBAR_MIN_THUMB);

    let scroll_range = (content_size - viewport_size) as f32;
    let thumb_range = (viewport_size - thumb_size) as f32;
    let thumb_pos = if scroll_range > 0.0 {
        ((scroll_offset as f32 / scroll_range) * thumb_range) as u32
    } else {
        0
    };

    (thumb_pos, thumb_size)
}

pub fn draw_vertical(idx: usize, x: u32, y: u32, height: u32) {
    if idx >= MAX_WINDOWS {
        return;
    }

    let content_h = WINDOWS[idx].content_height.load(Ordering::Relaxed);
    if content_h <= height {
        return;
    }

    let scroll_y = WINDOWS[idx].scroll_y.load(Ordering::Relaxed);
    let (thumb_pos, thumb_size) = calc_thumb(height, content_h, scroll_y);

    fill_rect(x, y, SCROLLBAR_WIDTH, height, SCROLLBAR_BG);

    let thumb_color = if WINDOWS[idx].scrollbar_dragging.load(Ordering::Relaxed) {
        SCROLLBAR_THUMB_HOVER
    } else {
        SCROLLBAR_THUMB
    };
    fill_rect(x + 2, y + thumb_pos, SCROLLBAR_WIDTH - 4, thumb_size, thumb_color);
}

pub fn draw_horizontal(idx: usize, x: u32, y: u32, width: u32) {
    if idx >= MAX_WINDOWS {
        return;
    }

    let content_w = WINDOWS[idx].content_width.load(Ordering::Relaxed);
    if content_w <= width {
        return;
    }

    let scroll_x = WINDOWS[idx].scroll_x.load(Ordering::Relaxed);
    let (thumb_pos, thumb_size) = calc_thumb(width, content_w, scroll_x);

    fill_rect(x, y, width, SCROLLBAR_WIDTH, SCROLLBAR_BG);

    let thumb_color = if WINDOWS[idx].scrollbar_dragging.load(Ordering::Relaxed) {
        SCROLLBAR_THUMB_HOVER
    } else {
        SCROLLBAR_THUMB
    };
    fill_rect(x + thumb_pos, y + 2, thumb_size, SCROLLBAR_WIDTH - 4, thumb_color);
}

pub fn needs_vertical(idx: usize, viewport_height: u32) -> bool {
    if idx >= MAX_WINDOWS {
        return false;
    }
    WINDOWS[idx].content_height.load(Ordering::Relaxed) > viewport_height
}

pub fn needs_horizontal(idx: usize, viewport_width: u32) -> bool {
    if idx >= MAX_WINDOWS {
        return false;
    }
    WINDOWS[idx].content_width.load(Ordering::Relaxed) > viewport_width
}

pub fn set_content_size(idx: usize, width: u32, height: u32) {
    if idx >= MAX_WINDOWS {
        return;
    }
    WINDOWS[idx].content_width.store(width, Ordering::Relaxed);
    WINDOWS[idx].content_height.store(height, Ordering::Relaxed);
}

pub fn get_scroll(idx: usize) -> (i32, i32) {
    if idx >= MAX_WINDOWS {
        return (0, 0);
    }
    (
        WINDOWS[idx].scroll_x.load(Ordering::Relaxed),
        WINDOWS[idx].scroll_y.load(Ordering::Relaxed),
    )
}

pub fn set_scroll(idx: usize, scroll_x: i32, scroll_y: i32) {
    if idx >= MAX_WINDOWS {
        return;
    }

    let viewport_w = WINDOWS[idx].width.load(Ordering::Relaxed);
    let viewport_h = WINDOWS[idx].height.load(Ordering::Relaxed) - TITLE_BAR_HEIGHT;
    let content_w = WINDOWS[idx].content_width.load(Ordering::Relaxed);
    let content_h = WINDOWS[idx].content_height.load(Ordering::Relaxed);

    let max_scroll_x = (content_w.saturating_sub(viewport_w)) as i32;
    let max_scroll_y = (content_h.saturating_sub(viewport_h)) as i32;

    let clamped_x = scroll_x.clamp(0, max_scroll_x);
    let clamped_y = scroll_y.clamp(0, max_scroll_y);

    WINDOWS[idx].scroll_x.store(clamped_x, Ordering::Relaxed);
    WINDOWS[idx].scroll_y.store(clamped_y, Ordering::Relaxed);
}

pub fn scroll_by(idx: usize, delta_x: i32, delta_y: i32) {
    if idx >= MAX_WINDOWS {
        return;
    }

    let current_x = WINDOWS[idx].scroll_x.load(Ordering::Relaxed);
    let current_y = WINDOWS[idx].scroll_y.load(Ordering::Relaxed);
    set_scroll(idx, current_x + delta_x, current_y + delta_y);
}

pub fn handle_vertical_click(idx: usize, bar_x: u32, bar_y: u32, bar_h: u32, mx: i32, my: i32, pressed: bool) -> bool {
    if idx >= MAX_WINDOWS {
        return false;
    }

    let content_h = WINDOWS[idx].content_height.load(Ordering::Relaxed);
    if content_h <= bar_h {
        return false;
    }

    if mx < bar_x as i32 || mx >= (bar_x + SCROLLBAR_WIDTH) as i32 {
        return false;
    }
    if my < bar_y as i32 || my >= (bar_y + bar_h) as i32 {
        return false;
    }

    if pressed {
        let scroll_y = WINDOWS[idx].scroll_y.load(Ordering::Relaxed);
        let (thumb_pos, thumb_size) = calc_thumb(bar_h, content_h, scroll_y);
        let relative_y = (my - bar_y as i32) as u32;

        if relative_y >= thumb_pos && relative_y < thumb_pos + thumb_size {
            WINDOWS[idx].scrollbar_dragging.store(true, Ordering::Relaxed);
            WINDOWS[idx].scrollbar_drag_offset.store((relative_y - thumb_pos) as i32, Ordering::Relaxed);
        } else {
            let target_pos = if relative_y < thumb_pos {
                relative_y
            } else {
                relative_y.saturating_sub(thumb_size)
            };
            let thumb_range = bar_h.saturating_sub(thumb_size);
            if thumb_range > 0 {
                let scroll_range = content_h - bar_h;
                let new_scroll = ((target_pos as f32 / thumb_range as f32) * scroll_range as f32) as i32;
                set_scroll(idx, 0, new_scroll);
            }
        }
    } else {
        WINDOWS[idx].scrollbar_dragging.store(false, Ordering::Relaxed);
    }

    true
}

pub fn handle_drag(idx: usize, bar_y: u32, bar_h: u32, my: i32) {
    if idx >= MAX_WINDOWS {
        return;
    }

    if !WINDOWS[idx].scrollbar_dragging.load(Ordering::Relaxed) {
        return;
    }

    let content_h = WINDOWS[idx].content_height.load(Ordering::Relaxed);
    if content_h <= bar_h {
        WINDOWS[idx].scrollbar_dragging.store(false, Ordering::Relaxed);
        return;
    }

    let scroll_y = WINDOWS[idx].scroll_y.load(Ordering::Relaxed);
    let (_, thumb_size) = calc_thumb(bar_h, content_h, scroll_y);
    let drag_offset = WINDOWS[idx].scrollbar_drag_offset.load(Ordering::Relaxed);

    let new_thumb_pos = (my - bar_y as i32 - drag_offset).max(0) as u32;
    let thumb_range = bar_h.saturating_sub(thumb_size);

    if thumb_range > 0 {
        let scroll_range = content_h - bar_h;
        let new_scroll = ((new_thumb_pos.min(thumb_range) as f32 / thumb_range as f32) * scroll_range as f32) as i32;
        set_scroll(idx, 0, new_scroll);
    }
}

pub fn is_dragging(idx: usize) -> bool {
    if idx >= MAX_WINDOWS {
        return false;
    }
    WINDOWS[idx].scrollbar_dragging.load(Ordering::Relaxed)
}

pub fn stop_dragging(idx: usize) {
    if idx >= MAX_WINDOWS {
        return;
    }
    WINDOWS[idx].scrollbar_dragging.store(false, Ordering::Relaxed);
}

pub fn reset(idx: usize) {
    if idx >= MAX_WINDOWS {
        return;
    }
    WINDOWS[idx].scroll_x.store(0, Ordering::Relaxed);
    WINDOWS[idx].scroll_y.store(0, Ordering::Relaxed);
    WINDOWS[idx].content_width.store(0, Ordering::Relaxed);
    WINDOWS[idx].content_height.store(0, Ordering::Relaxed);
    WINDOWS[idx].scrollbar_dragging.store(false, Ordering::Relaxed);
}
