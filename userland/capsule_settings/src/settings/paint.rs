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

use super::state::{State, LABELS};
use super::theme::{BACKGROUND, FOREGROUND, SELECTED};

const TEXT_LEFT: u32 = 16;
const MARK_LEFT: u32 = 20;
const LABEL_LEFT: u32 = 60;
const FIRST_ROW_Y: u32 = 56;
const ROW_HEIGHT: u32 = 26;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    fb.clear(BACKGROUND);
    fb.text(TEXT_LEFT, 18, b"settings", FOREGROUND);
    let mut y = FIRST_ROW_Y;
    for (i, label) in LABELS.iter().enumerate() {
        let mark: &[u8] = if state.on[i] { b"[x]" } else { b"[ ]" };
        let color = if i == state.cursor { SELECTED } else { FOREGROUND };
        fb.text(MARK_LEFT, y, mark, color);
        fb.text(LABEL_LEFT, y, label, color);
        y += ROW_HEIGHT;
    }
}
