// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::main::draw_string;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};
use crate::graphics::window::settings::state::SIDEBAR_WIDTH;

const BG_DARK: u32 = 0xFF0D1117;
const BG_SELECTED: u32 = 0xFF1F6FEB;
const TEXT_PRIMARY: u32 = 0xFFE6EDF3;
const TEXT_DIM: u32 = 0xFF7D8590;
const BORDER: u32 = 0xFF30363D;

static LABELS: [&[u8]; 12] = [
    b"Privacy", b"Network", b"Appearance", b"System", b"Power", b"Kernel",
    b"Display", b"Keyboard", b"Mouse", b"Sound", b"Accessibility", b"Lock Screen",
];
static ACCENTS: [u32; 12] = [
    0xFF8B5CF6, 0xFF3B82F6, 0xFFF59E0B, 0xFF10B981, 0xFFEF4444, 0xFF06B6D4,
    0xFF14B8A6, 0xFFF97316, 0xFFA855F7, 0xFF22C55E, 0xFF3B82F6, 0xFFEC4899,
];

pub(super) fn draw_sidebar(x: u32, y: u32, h: u32, current_page: u8) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, BG_DARK);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, BORDER);
    draw_string(x + 20, y + 20, b"Settings", TEXT_PRIMARY);
    fill_rect(x + 16, y + 42, SIDEBAR_WIDTH - 32, 1, BORDER);
    for i in 0..12 {
        let ty = y + 56 + (i as u32) * 32;
        if ty + 32 > y + h { break; }
        let is_sel = current_page == i as u8;
        if is_sel {
            fill_rounded_rect(x + 8, ty, SIDEBAR_WIDTH - 16, 28, 6, BG_SELECTED);
            fill_rect(x + 8, ty, 3, 28, ACCENTS[i]);
        }
        let text_col = if is_sel { TEXT_PRIMARY } else { TEXT_DIM };
        draw_string(x + 20, ty + 8, LABELS[i], text_col);
    }
}
