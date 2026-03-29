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

use crate::display::gop::fill_rect;
use crate::menu::types::MenuState;

const BAR_X: u32 = 100;
const BAR_Y: u32 = 450;
const BAR_WIDTH: u32 = 400;
const BAR_HEIGHT: u32 = 8;
const BAR_BG: u32 = 0x282832;
const BAR_FG: u32 = 0x64B4FF;

pub fn render_timeout_bar(state: &MenuState) {
    if !state.visible || state.timeout_ms == 0 {
        return;
    }

    fill_rect(BAR_X, BAR_Y, BAR_WIDTH, BAR_HEIGHT, BAR_BG);

    let remaining = state.remaining_ms();
    let total = state.timeout_ms;
    let fill_width = ((BAR_WIDTH as u64 * remaining) / total) as u32;

    if fill_width > 0 {
        fill_rect(BAR_X, BAR_Y, fill_width, BAR_HEIGHT, BAR_FG);
    }
}
