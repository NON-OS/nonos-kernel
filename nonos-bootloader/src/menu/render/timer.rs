// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::font::draw_string;
use crate::display::gop::fill_rect;
use crate::menu::types::MenuState;

const BAR_X: u32 = 324;
const BAR_Y: u32 = 448;
const BAR_W: u32 = 392;
const BAR_H: u32 = 6;
const COL_BG: u32 = 0x181820;
const COL_FILL: u32 = 0x40C080;
const COL_TEXT: u32 = 0x606878;

pub fn render_timeout_bar(state: &MenuState) {
    if !state.visible || state.timeout_ms == 0 {
        return;
    }

    let remaining = state.remaining_ms();
    let elapsed = state.timeout_ms.saturating_sub(remaining);
    let progress = ((elapsed * BAR_W as u64) / state.timeout_ms) as u32;

    fill_rect(BAR_X, BAR_Y, BAR_W, BAR_H, COL_BG);
    if progress > 0 && progress <= BAR_W {
        fill_rect(BAR_X, BAR_Y, progress, BAR_H, COL_FILL);
    }

    let secs = ((remaining + 999) / 1000) as u32;
    let msg: &[u8] = match secs {
        0 | 1 => b"Auto-boot in 1 second...",
        2 => b"Auto-boot in 2 seconds...",
        _ => b"Auto-boot in 3 seconds...",
    };

    draw_string(BAR_X, BAR_Y + 14, msg, COL_TEXT);
}
