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

/*
 * Progress Bar Component.
 */

use crate::display::constants::*;
use crate::display::gop::{draw_rect, fill_rect};

pub fn draw_progress_bar(x: u32, y: u32, w: u32, h: u32, progress: u32, max: u32, color: u32) {
    fill_rect(x, y, w, h, COLOR_PROGRESS_BG);

    if max > 0 && progress > 0 {
        let fill_w = (w * progress.min(max)) / max;
        fill_rect(x, y, fill_w, h, color);
    }

    draw_rect(x, y, w, h, COLOR_GLASS_BORDER);
}
