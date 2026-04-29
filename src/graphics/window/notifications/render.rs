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

use super::icon;
use super::layout::{notification_rect, ACTION_BTN_H, ACTION_BTN_W};
use super::storage::{MAX_NOTIFICATIONS, NOTIFICATIONS};
use super::timer::{clear_expired, progress};
use super::types::Notification;
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::{ACCENT, TEXT_PRIMARY, TEXT_SECONDARY};

const BG_COLOR: u32 = 0xF0202028;
const ACTION_BG: u32 = 0xFF2A3A4A;
const ACTION_BG_HOVER: u32 = 0xFF3A4A5A;

pub(crate) fn draw() {
    clear_expired();
    let mut drawn = 0u32;
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if NOTIFICATIONS[i].active {
                draw_notification(drawn, i, &NOTIFICATIONS[i]);
                drawn += 1;
            }
        }
    }
}

fn draw_notification(index: u32, slot: usize, n: &Notification) {
    let has_actions = n.action_count > 0;
    let layout = notification_rect(index, has_actions);
    draw_shadow(&layout);
    primitives::rounded_rect(layout.x, layout.y, layout.width, layout.height, 12, BG_COLOR);
    icon::draw(&layout, n.ntype);
    draw_text(&layout, n);
    icon::draw_close_button(&layout, false);
    if has_actions {
        draw_actions(&layout, n);
    }
    let p = progress(slot);
    if p < 100 {
        icon::draw_progress_bar(&layout, 100 - p);
    }
}

fn draw_shadow(layout: &super::layout::NotificationLayout) {
    for s in 1..=4u32 {
        let alpha = (24 - s * 5) << 24;
        primitives::rounded_rect(layout.x + s / 2, layout.y + s + 1, layout.width, layout.height, 12, alpha);
    }
}

fn draw_text(layout: &super::layout::NotificationLayout, n: &Notification) {
    let (tx, ty) = super::layout::title_position(layout);
    let (mx, my) = super::layout::message_position(layout);
    if n.title_len > 0 {
        text::draw(tx, ty, &n.title[..n.title_len.min(28)], TEXT_PRIMARY);
    }
    if n.message_len > 0 {
        text::draw(mx, my, &n.message[..n.message_len.min(32)], TEXT_SECONDARY);
    }
}

fn draw_actions(layout: &super::layout::NotificationLayout, n: &Notification) {
    for i in 0..n.action_count as usize {
        let (ax, ay) = super::layout::action_position(layout, i);
        primitives::rounded_rect(ax, ay, ACTION_BTN_W, ACTION_BTN_H, 6, ACTION_BG);
        let label = &n.actions[i].label[..n.actions[i].label_len];
        text::draw(ax + 8, ay + 6, label, ACCENT);
    }
}
