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

use crate::graphics::framebuffer::dimensions;

pub(super) const NOTIF_W: u32 = 340;
pub(super) const NOTIF_H: u32 = 72;
pub(super) const NOTIF_H_WITH_ACTIONS: u32 = 96;
pub(super) const PADDING: u32 = 12;
pub(super) const ICON_SIZE: u32 = 28;
pub(super) const ICON_MARGIN: u32 = 14;
pub(super) const TEXT_X: u32 = 52;
pub(super) const CLOSE_SIZE: u32 = 20;
pub(super) const ACTION_BTN_W: u32 = 80;
pub(super) const ACTION_BTN_H: u32 = 24;
pub(super) const ACTION_BTN_GAP: u32 = 8;

pub(super) struct NotificationLayout {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

pub(super) fn screen_anchor() -> (u32, u32) {
    let (sw, _) = dimensions();
    let x = sw - NOTIF_W - PADDING;
    let y = 48u32;
    (x, y)
}

pub(super) fn notification_rect(index: u32, has_actions: bool) -> NotificationLayout {
    let (start_x, start_y) = screen_anchor();
    let h = if has_actions { NOTIF_H_WITH_ACTIONS } else { NOTIF_H };
    let mut y = start_y;
    for _ in 0..index {
        y += NOTIF_H + PADDING;
    }
    NotificationLayout { x: start_x, y, width: NOTIF_W, height: h }
}

pub(super) fn icon_position(layout: &NotificationLayout) -> (u32, u32) {
    (layout.x + ICON_MARGIN, layout.y + (layout.height - ICON_SIZE) / 2 - 8)
}

pub(super) fn title_position(layout: &NotificationLayout) -> (u32, u32) {
    (layout.x + TEXT_X, layout.y + 14)
}

pub(super) fn message_position(layout: &NotificationLayout) -> (u32, u32) {
    (layout.x + TEXT_X, layout.y + 32)
}

pub(super) fn close_position(layout: &NotificationLayout) -> (u32, u32) {
    (layout.x + layout.width - CLOSE_SIZE - 8, layout.y + 8)
}

pub(super) fn action_position(layout: &NotificationLayout, idx: usize) -> (u32, u32) {
    let x = layout.x + TEXT_X + (ACTION_BTN_W + ACTION_BTN_GAP) * idx as u32;
    let y = layout.y + layout.height - ACTION_BTN_H - 10;
    (x, y)
}
