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

use crate::calc::format::{format, DISPLAY_MAX};
use crate::calc::layout::{DISPLAY_H, PADDING};
use crate::calc::state::State;
use crate::calc::theme::{DISPLAY_BG, DISPLAY_TEXT, ERROR_TEXT};

const GLYPH_ADVANCE: u32 = 8;
const TEXT_LEFT_INSET: u32 = 16;
const TEXT_TOP_INSET: u32 = 36;

pub fn paint(fb: &mut PaintBuffer, state: &State) {
    let w = fb.width - PADDING * 2;
    fb.fill_rect(PADDING, PADDING, w, DISPLAY_H, DISPLAY_BG);
    let mut buf = [0u8; DISPLAY_MAX];
    let len = if state.error {
        let err = b"ERROR";
        let n = err.len().min(buf.len());
        buf[..n].copy_from_slice(&err[..n]);
        n
    } else {
        format(state.display, state.decimal_pos, &mut buf)
    };
    let color = if state.error { ERROR_TEXT } else { DISPLAY_TEXT };
    let text_w = (len as u32) * GLYPH_ADVANCE;
    let text_x = if text_w + TEXT_LEFT_INSET < w {
        PADDING + w - TEXT_LEFT_INSET - text_w
    } else {
        PADDING + TEXT_LEFT_INSET
    };
    fb.text(text_x, PADDING + TEXT_TOP_INSET, &buf[..len], color);
}
