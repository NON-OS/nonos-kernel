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

use super::constants::{LINE_HEIGHT, TEXT_LEFT, TOP_PADDING};
use super::draw_input_line::draw_input_line;
use crate::term::state::State;
use crate::term::theme::{BACKGROUND, FOREGROUND};

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    fb.clear(BACKGROUND);
    let mut y = TOP_PADDING;
    for row in state.scrollback.visible().rows() {
        fb.text(TEXT_LEFT, y, row, FOREGROUND);
        y += LINE_HEIGHT;
    }
    draw_input_line(state, fb, y);
}
