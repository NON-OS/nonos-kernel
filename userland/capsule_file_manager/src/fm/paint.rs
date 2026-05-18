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

use super::entries::ENTRIES;
use super::state::State;
use super::theme::{BACKGROUND, FOREGROUND, OPENED, SELECTED};

const TEXT_LEFT: u32 = 16;
const ENTRY_LEFT: u32 = 36;
const FIRST_ROW_Y: u32 = 56;
const ROW_HEIGHT: u32 = 26;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    fb.clear(BACKGROUND);
    fb.text(TEXT_LEFT, 18, b"file_manager  cwd=/", FOREGROUND);
    let mut y = FIRST_ROW_Y;
    for (i, entry) in ENTRIES.iter().enumerate() {
        let opened = state.opened == Some(i);
        let color = if opened {
            OPENED
        } else if i == state.cursor {
            SELECTED
        } else {
            FOREGROUND
        };
        if i == state.cursor {
            fb.text(TEXT_LEFT, y, b">", SELECTED);
        }
        fb.text(ENTRY_LEFT, y, entry, color);
        y += ROW_HEIGHT;
    }
}
