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

use nonos_app_skeleton::PaintBuffer;

use crate::calc::buttons::{Button, Role};
use crate::calc::theme::{BTN_EQ, BTN_FUNC, BTN_NUM, BTN_OP, BTN_TEXT};

const GLYPH_ADVANCE: u32 = 8;
const GLYPH_HEIGHT: u32 = 16;

pub fn paint(fb: &mut PaintBuffer, btn: &Button, x: u32, y: u32, w: u32, h: u32) {
    let bg = match btn.role {
        Role::Function => BTN_FUNC,
        Role::Number => BTN_NUM,
        Role::Operator => BTN_OP,
        Role::Equals => BTN_EQ,
    };
    fb.fill_rect(x, y, w, h, bg);
    let label_w = (btn.label.len() as u32) * GLYPH_ADVANCE;
    let tx = x + w.saturating_sub(label_w) / 2;
    let ty = y + h.saturating_sub(GLYPH_HEIGHT) / 2;
    fb.text(tx, ty, btn.label, BTN_TEXT);
}
