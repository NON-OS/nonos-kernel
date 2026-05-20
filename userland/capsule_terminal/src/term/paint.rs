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

use super::state::{State, COLS};
use super::theme::{BACKGROUND, FOREGROUND, PROMPT};

const LINE_HEIGHT: u32 = 22;
const TEXT_LEFT: u32 = 12;
const FIRST_ROW_Y: u32 = 20;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    fb.clear(BACKGROUND);
    let mut y = FIRST_ROW_Y;
    for i in 0..state.rows {
        fb.text(TEXT_LEFT, y, &state.hist[i][..state.hist_len[i]], FOREGROUND);
        y += LINE_HEIGHT;
    }
    let mut prompt = [0u8; COLS + 2];
    prompt[0] = b'$';
    prompt[1] = b' ';
    let n = state.len.min(COLS);
    prompt[2..2 + n].copy_from_slice(&state.line[..n]);
    fb.text(TEXT_LEFT, y, &prompt[..2], PROMPT);
    fb.text(TEXT_LEFT + 16, y, &prompt[2..2 + n], FOREGROUND);
}
