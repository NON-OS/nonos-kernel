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

use super::state::*;
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::*;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::dimensions;
use core::sync::atomic::Ordering;

const NOTIF_W: u32 = 320;
const NOTIF_H: u32 = 60;
const PADDING: u32 = 12;

pub(crate) fn draw() {
    clear_expired();
    let (sw, _) = dimensions();
    let start_x = sw - NOTIF_W - PADDING;
    let start_y = 48u32;
    let mut drawn = 0u32;

    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if NOTIFICATIONS[i].active {
                let y = start_y + drawn * (NOTIF_H + PADDING);
                draw_notification(start_x, y, &NOTIFICATIONS[i]);
                drawn += 1;
            }
        }
    }
}

fn draw_notification(x: u32, y: u32, n: &Notification) {
    for shadow in 0..4u32 {
        primitives::rounded_rect(
            x + shadow / 2,
            y + shadow + 2,
            NOTIF_W,
            NOTIF_H,
            12,
            (20 - shadow * 4) << 24,
        );
    }
    primitives::rounded_rect(x, y, NOTIF_W, NOTIF_H, 12, 0xF02C2C2E);

    let icon_color = match n.ntype {
        NOTIFY_SUCCESS => SUCCESS,
        NOTIFY_WARNING => WARNING,
        NOTIFY_ERROR => ERROR,
        _ => ACCENT,
    };
    primitives::rounded_rect(x + 14, y + 18, 24, 24, 6, icon_color);
    let icon_char = match n.ntype {
        NOTIFY_SUCCESS => 0x04,
        NOTIFY_WARNING => b'!',
        NOTIFY_ERROR => b'X',
        _ => b'i',
    };
    draw_char(x + 22, y + 22, icon_char, TEXT_INVERSE);

    if n.message_len > 0 {
        let display_len = n.message_len.min(30);
        text::draw(x + 48, y + 22, &n.message[..display_len], TEXT_PRIMARY);
    }
    draw_char(x + NOTIF_W - 24, y + 8, b'x', TEXT_SECONDARY);
}

fn clear_expired() {
    let time = CURRENT_TIME_MS.load(Ordering::Relaxed);
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if NOTIFICATIONS[i].active
                && time.saturating_sub(NOTIFICATIONS[i].created_at) > NOTIFICATION_DURATION_MS
            {
                NOTIFICATIONS[i].active = false;
                NOTIFICATION_COUNT.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}
