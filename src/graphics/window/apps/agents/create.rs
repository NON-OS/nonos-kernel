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

use super::create_state::*;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};

const CARD: u32 = 0xFF14141C;
const ACCENT: u32 = 0xFF00D4FF;
const DIM: u32 = 0xFF606068;
const LIME: u32 = 0xFF00E676;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(super) fn draw(x: u32, y: u32, w: u32, _h: u32) {
    txt(x + 20, y + 20, b"Create New Agent", 0xFFFFFFFF);
    draw_presets(x + 20, y + 50, w - 40);
    txt(x + 20, y + 140, b"Or custom:", DIM);
    txt(x + 20, y + 160, b"Name:", DIM);
    draw_input(x + 20, y + 180, 300, name_buf(), name_len(), focus() == 0);
    txt(x + 20, y + 230, b"System Prompt:", DIM);
    draw_input(x + 20, y + 250, w - 40, prompt_buf(), prompt_len(), focus() == 1);
    fill_rounded_rect(x + 20, y + 310, 120, 36, 6, ACCENT);
    txt(x + 40, y + 320, b"Create", 0xFF000000);
}

fn draw_presets(x: u32, y: u32, _w: u32) {
    txt(x, y, b"Quick Start Presets:", 0xFFFFFFFF);
    let presets = crate::agents::presets::list_presets();
    let mut px = x;
    let sel = preset_idx() as usize;
    for (i, (name, _)) in presets.iter().enumerate() {
        let bg = if i == sel { LIME } else { CARD };
        let fg = if i == sel { 0xFF000000 } else { 0xFFFFFFFF };
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len()).min(14);
        fill_rounded_rect(px, y + 20, len as u32 * 8 + 16, 28, 6, bg);
        txt(px + 8, y + 26, &name[..len], fg);
        px += len as u32 * 8 + 24;
        if px > x + 400 {
            break;
        }
    }
}

fn draw_input(x: u32, y: u32, w: u32, buf: &[u8], len: usize, focused: bool) {
    let bg = if focused { 0xFF1E1E28 } else { CARD };
    fill_rounded_rect(x, y, w, 36, 6, bg);
    let show = len.min(40);
    for i in 0..show {
        draw_char(x + 8 + i as u32 * 8, y + 10, buf[i], 0xFFFFFFFF);
    }
    if focused {
        fill_rect(x + 8 + show as u32 * 8, y + 8, 2, 20, ACCENT);
    }
}

pub(crate) use super::create_input::{handle_click, handle_key};
