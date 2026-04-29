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

use super::{devices, state::get_state};
use crate::graphics::design_system::colors::*;
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::fill_rect;

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 44;
const LABEL_X: u32 = 24;
const SLIDER_X: u32 = 180;
const SLIDER_W: u32 = 180;

pub fn draw(x: u32, y: u32, w: u32, _h: u32) {
    let state = get_state();
    draw_header(x, y);
    draw_output_section(x, y, w, &state);
    draw_input_section(x, y, &state);
}

fn draw_header(x: u32, y: u32) {
    draw_text(x + LABEL_X, y + 24, b"Sound", TEXT_PRIMARY);
    draw_text(x + LABEL_X, y + 48, b"Output, input, and alert sounds", TEXT_SECONDARY);
}

fn draw_slider(x: u32, y: u32, val: u8, muted: bool) {
    let color = if muted { TEXT_DISABLED } else { ACCENT };
    let fill_w = (SLIDER_W * val as u32) / 100;
    fill_rect(x + SLIDER_X, y + 2, SLIDER_W, 12, BG_INPUT);
    fill_rect(x + SLIDER_X, y + 2, fill_w, 12, color);
}

fn draw_output_section(x: u32, y: u32, w: u32, s: &super::state::SoundState) {
    let sy = y + SECTION_Y;
    draw_text(x + LABEL_X, sy, b"Output Volume", TEXT_PRIMARY);
    draw_slider(x, sy, s.output_volume, s.output_muted);
    let mute_txt = if s.output_muted { b"Unmute" as &[u8] } else { b"Mute" };
    draw_text(x + SLIDER_X + SLIDER_W + 16, sy, mute_txt, TEXT_LINK);
    let sy2 = y + SECTION_Y + ROW_HEIGHT;
    draw_text(x + LABEL_X, sy2, b"Output Device", TEXT_PRIMARY);
    let dev_name = devices::output_device_name(s.output_device_id);
    fill_rect(x + w - 220, sy2 - 4, 180, 28, BG_INPUT);
    draw_text(x + w - 212, sy2, dev_name.as_bytes(), TEXT_PRIMARY);
    let sy3 = y + SECTION_Y + ROW_HEIGHT * 2;
    draw_text(x + LABEL_X, sy3, b"Balance", TEXT_PRIMARY);
    draw_text(x + SLIDER_X - 16, sy3, b"L", TEXT_SECONDARY);
    draw_balance_slider(x, sy3, s.balance);
    draw_text(x + SLIDER_X + SLIDER_W + 8, sy3, b"R", TEXT_SECONDARY);
}

fn draw_balance_slider(x: u32, y: u32, val: u8) {
    fill_rect(x + SLIDER_X, y + 2, SLIDER_W, 12, BG_INPUT);
    let pos = (SLIDER_W * val as u32) / 100;
    fill_rect(x + SLIDER_X + pos.saturating_sub(4), y, 8, 16, ACCENT);
}

fn draw_input_section(x: u32, y: u32, s: &super::state::SoundState) {
    let sy = y + SECTION_Y + ROW_HEIGHT * 3 + 20;
    draw_text(x + LABEL_X, sy, b"Input Volume", TEXT_PRIMARY);
    draw_slider(x, sy, s.input_volume, s.input_muted);
}
