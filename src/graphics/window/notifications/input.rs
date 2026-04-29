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

use super::actions::{dismiss, execute};
use super::layout::{
    action_position, close_position, notification_rect, ACTION_BTN_H, ACTION_BTN_W,
    CLOSE_SIZE,
};
use super::storage::{MAX_NOTIFICATIONS, NOTIFICATIONS};

pub(crate) fn handle_click(mx: i32, my: i32) -> bool {
    let mut drawn = 0u32;
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if NOTIFICATIONS[i].active {
                if handle_notification_click(mx, my, drawn, i, &NOTIFICATIONS[i]) {
                    return true;
                }
                drawn += 1;
            }
        }
    }
    false
}

fn handle_notification_click(
    mx: i32,
    my: i32,
    index: u32,
    slot: usize,
    n: &super::types::Notification,
) -> bool {
    let has_actions = n.action_count > 0;
    let layout = notification_rect(index, has_actions);
    let (cx, cy) = close_position(&layout);
    if hit_test(mx, my, cx, cy, CLOSE_SIZE, CLOSE_SIZE) {
        dismiss(slot);
        return true;
    }
    for a in 0..n.action_count as usize {
        let (ax, ay) = action_position(&layout, a);
        if hit_test(mx, my, ax, ay, ACTION_BTN_W, ACTION_BTN_H) {
            execute(slot, a);
            return true;
        }
    }
    hit_test(mx, my, layout.x, layout.y, layout.width, layout.height)
}

fn hit_test(mx: i32, my: i32, x: u32, y: u32, w: u32, h: u32) -> bool {
    mx >= x as i32 && mx < (x + w) as i32 && my >= y as i32 && my < (y + h) as i32
}
