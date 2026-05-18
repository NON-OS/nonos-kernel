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

use super::state::State;
use super::theme::{BACKGROUND, FOREGROUND, TITLE};

const WRAP_COLS: u32 = 48;
const GLYPH_ADVANCE: u32 = 9;
const LINE_HEIGHT: u32 = 20;
const TEXT_LEFT: u32 = 16;
const FIRST_LINE_Y: u32 = 48;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    fb.clear(BACKGROUND);
    fb.text(TEXT_LEFT, 18, b"text_editor", TITLE);
    let mut y = FIRST_LINE_Y;
    let mut col: u32 = 0;
    for i in 0..state.len {
        let ch = state.buf[i];
        if ch == b'\n' || col == WRAP_COLS {
            y += LINE_HEIGHT;
            col = 0;
            if ch == b'\n' {
                continue;
            }
        }
        fb.text(TEXT_LEFT + col * GLYPH_ADVANCE, y, &state.buf[i..i + 1], FOREGROUND);
        col += 1;
    }
}
