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

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use crate::graphics::framebuffer::{fill_rect, dimensions, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW};
use crate::graphics::font::draw_char;

const MAX_NOTIFICATIONS: usize = 5;
const MAX_MESSAGE_LEN: usize = 64;
const NOTIFICATION_DURATION_MS: u64 = 5000;

pub const NOTIFY_INFO: u8 = 0;
pub const NOTIFY_SUCCESS: u8 = 1;
pub const NOTIFY_WARNING: u8 = 2;
pub const NOTIFY_ERROR: u8 = 3;

struct Notification {
    active: bool,
    ntype: u8,
    message: [u8; MAX_MESSAGE_LEN],
    message_len: usize,
    created_at: u64,
}

impl Notification {
    const fn new() -> Self {
        Self {
            active: false,
            ntype: 0,
            message: [0u8; MAX_MESSAGE_LEN],
            message_len: 0,
            created_at: 0,
        }
    }
}

static mut NOTIFICATIONS: [Notification; MAX_NOTIFICATIONS] = [
    Notification::new(),
    Notification::new(),
    Notification::new(),
    Notification::new(),
    Notification::new(),
];
static NOTIFICATION_COUNT: AtomicU8 = AtomicU8::new(0);
static CURRENT_TIME_MS: AtomicU64 = AtomicU64::new(0);

fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

pub fn update_time(time_ms: u64) {
    CURRENT_TIME_MS.store(time_ms, Ordering::Relaxed);
}

pub fn push(ntype: u8, message: &[u8]) {
    let msg_len = message.len().min(MAX_MESSAGE_LEN);
    let time = CURRENT_TIME_MS.load(Ordering::Relaxed);

    // SAFETY: Single-threaded notification access
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if !NOTIFICATIONS[i].active {
                NOTIFICATIONS[i].active = true;
                NOTIFICATIONS[i].ntype = ntype;
                NOTIFICATIONS[i].message_len = msg_len;
                NOTIFICATIONS[i].created_at = time;
                for j in 0..msg_len {
                    NOTIFICATIONS[i].message[j] = message[j];
                }
                NOTIFICATION_COUNT.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        for i in 0..MAX_NOTIFICATIONS - 1 {
            NOTIFICATIONS[i] = core::mem::replace(&mut NOTIFICATIONS[i + 1], Notification::new());
        }
        let last = MAX_NOTIFICATIONS - 1;
        NOTIFICATIONS[last].active = true;
        NOTIFICATIONS[last].ntype = ntype;
        NOTIFICATIONS[last].message_len = msg_len;
        NOTIFICATIONS[last].created_at = time;
        for j in 0..msg_len {
            NOTIFICATIONS[last].message[j] = message[j];
        }
    }
}

pub fn info(message: &[u8]) {
    push(NOTIFY_INFO, message);
}

pub fn success(message: &[u8]) {
    push(NOTIFY_SUCCESS, message);
}

pub fn warning(message: &[u8]) {
    push(NOTIFY_WARNING, message);
}

pub fn error(message: &[u8]) {
    push(NOTIFY_ERROR, message);
}

pub fn clear_expired() {
    let time = CURRENT_TIME_MS.load(Ordering::Relaxed);

    // SAFETY: Single-threaded notification access
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if NOTIFICATIONS[i].active {
                if time.saturating_sub(NOTIFICATIONS[i].created_at) > NOTIFICATION_DURATION_MS {
                    NOTIFICATIONS[i].active = false;
                    NOTIFICATION_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }
}

pub fn draw() {
    clear_expired();

    let (screen_w, _) = dimensions();
    let notif_w = 300u32;
    let notif_h = 50u32;
    let padding = 10u32;
    let start_x = screen_w - notif_w - padding;
    let start_y = 45u32;

    let mut drawn = 0u32;

    // SAFETY: Read-only access to notifications for drawing
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if NOTIFICATIONS[i].active {
                let y = start_y + drawn * (notif_h + padding);

                let (bg_color, icon_color) = match NOTIFICATIONS[i].ntype {
                    NOTIFY_SUCCESS => (0xFF1A3A2A, COLOR_GREEN),
                    NOTIFY_WARNING => (0xFF3A3A1A, COLOR_YELLOW),
                    NOTIFY_ERROR => (0xFF3A1A1A, COLOR_RED),
                    _ => (0xFF1E2530, COLOR_ACCENT),
                };

                fill_rect(start_x, y, notif_w, notif_h, bg_color);
                fill_rect(start_x, y, 4, notif_h, icon_color);

                fill_rect(start_x + 12, y + 17, 16, 16, icon_color);

                if NOTIFICATIONS[i].message_len > 0 {
                    let display_len = NOTIFICATIONS[i].message_len.min(32);
                    draw_string(start_x + 36, y + 17, &NOTIFICATIONS[i].message[..display_len], COLOR_TEXT_WHITE);
                }

                fill_rect(start_x + notif_w - 20, y + 5, 14, 14, 0xFF4A5568);
                draw_char(start_x + notif_w - 17, y + 6, b'x', 0xFF7D8590);

                drawn += 1;
            }
        }
    }
}

pub fn handle_click(mx: i32, my: i32) -> bool {
    let (screen_w, _) = dimensions();
    let notif_w = 300u32;
    let notif_h = 50u32;
    let padding = 10u32;
    let start_x = (screen_w - notif_w - padding) as i32;
    let start_y = 45i32;

    let mut drawn = 0i32;

    // SAFETY: Single-threaded notification access
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if NOTIFICATIONS[i].active {
                let y = start_y + drawn * (notif_h as i32 + padding as i32);

                let close_x = start_x + notif_w as i32 - 20;
                if mx >= close_x && mx < close_x + 14 && my >= y + 5 && my < y + 19 {
                    NOTIFICATIONS[i].active = false;
                    NOTIFICATION_COUNT.fetch_sub(1, Ordering::Relaxed);
                    return true;
                }

                if mx >= start_x && mx < start_x + notif_w as i32 && my >= y && my < y + notif_h as i32 {
                    return true;
                }

                drawn += 1;
            }
        }
    }

    false
}

pub fn has_active() -> bool {
    NOTIFICATION_COUNT.load(Ordering::Relaxed) > 0
}
