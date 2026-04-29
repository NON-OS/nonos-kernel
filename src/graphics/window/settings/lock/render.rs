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

use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::design_system::colors::*;
use super::state::get_state;

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 44;
const LABEL_X: u32 = 24;
const VALUE_X: u32 = 260;

pub fn draw(x: u32, y: u32, w: u32, _h: u32) {
    let state = get_state();
    draw_header(x, y);
    draw_security_section(x, y, w, &state);
    draw_screensaver_section(x, y, w, &state);
}

fn draw_header(x: u32, y: u32) {
    draw_text(x + LABEL_X, y + 24, b"Lock Screen", TEXT_PRIMARY);
    draw_text(x + LABEL_X, y + 48, b"Security and screensaver options", TEXT_SECONDARY);
}

fn draw_toggle(x: u32, y: u32, label: &[u8], enabled: bool) {
    draw_text(x + LABEL_X, y, label, TEXT_PRIMARY);
    let status = if enabled { b"On" as &[u8] } else { b"Off" };
    let color = if enabled { SUCCESS } else { TEXT_SECONDARY };
    draw_text(x + VALUE_X, y, status, color);
}

fn draw_security_section(x: u32, y: u32, w: u32, s: &super::state::LockState) {
    let sy = y + SECTION_Y;
    draw_toggle(x, sy, b"Require Wallet Auth", s.require_wallet);
    let sy2 = y + SECTION_Y + ROW_HEIGHT;
    draw_toggle(x, sy2, b"Lock After Sleep", s.lock_after_sleep);
    let sy3 = y + SECTION_Y + ROW_HEIGHT * 2;
    draw_text(x + LABEL_X, sy3, b"Lock After Idle", TEXT_PRIMARY);
    let timeout = s.lock_timeout_label();
    fill_rect(x + w - 180, sy3 - 4, 140, 28, BG_INPUT);
    draw_text(x + w - 172, sy3, timeout.as_bytes(), TEXT_PRIMARY);
    let sy4 = y + SECTION_Y + ROW_HEIGHT * 3;
    draw_toggle(x, sy4, b"Show Message on Lock", s.show_message);
    let sy5 = y + SECTION_Y + ROW_HEIGHT * 4;
    draw_toggle(x, sy5, b"Auto Login", s.auto_login);
}

fn draw_screensaver_section(x: u32, y: u32, w: u32, s: &super::state::LockState) {
    let sy = y + SECTION_Y + ROW_HEIGHT * 5 + 20;
    draw_text(x + LABEL_X, sy, b"Screensaver", TEXT_PRIMARY);
    let ss_name = s.screensaver_name();
    fill_rect(x + w - 180, sy - 4, 140, 28, BG_INPUT);
    draw_text(x + w - 172, sy, ss_name.as_bytes(), TEXT_PRIMARY);
    let sy2 = sy + ROW_HEIGHT;
    draw_text(x + LABEL_X, sy2, b"Start After", TEXT_PRIMARY);
    let timeout_str = super::state::LOCK_TIMEOUTS
        .get(s.screensaver_timeout_idx as usize).map(|(s, _)| *s).unwrap_or("5 minutes");
    fill_rect(x + w - 180, sy2 - 4, 140, 28, BG_INPUT);
    draw_text(x + w - 172, sy2, timeout_str.as_bytes(), TEXT_PRIMARY);
}
