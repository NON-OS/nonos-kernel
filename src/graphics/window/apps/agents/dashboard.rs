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

use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rect;

const BG_CARD: u32 = 0xFF14141C;
const ACCENT: u32 = 0xFF00D4FF;
const GREEN: u32 = 0xFF00E676;
const DIM: u32 = 0xFF707080;
const WHITE: u32 = 0xFFE0E0E4;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(super) fn draw(x: u32, y: u32, w: u32, _h: u32) {
    fill_rect(x + 20, y + 10, (w - 60) / 2, 110, BG_CARD);
    fill_rect(x + (w / 2) + 10, y + 10, (w - 60) / 2, 110, BG_CARD);
    fill_rect(x + 20, y + 130, w - 40, 50, BG_CARD);
    draw_status(x + 32, y + 22);
    draw_tools(x + (w / 2) + 22, y + 22);
    txt(x + 32, y + 142, b"Agent Memory", ACCENT);
    txt(x + 32, y + 162, b"Context: 64KB per agent", DIM);
}

fn draw_status(x: u32, y: u32) {
    txt(x, y, b"Status", ACCENT);
    let running = crate::agents::is_running();
    let (status, color) =
        if running { (b"Running" as &[u8], GREEN) } else { (b"Idle" as &[u8], DIM) };
    txt(x, y + 28, b"State:", WHITE);
    txt(x + 58, y + 28, status, color);
    let cnt = crate::agents::registry::list_agents().len();
    txt(x, y + 46, b"Agents:", WHITE);
    txt(x + 66, y + 46, &[b'0' + cnt as u8], ACCENT);
    let tools = crate::agents::tools::list_tools().len();
    txt(x, y + 64, b"Tools:", WHITE);
    let mut tb = [b' ', b' ', b' '];
    if tools > 9 {
        tb = *b"10+";
    } else {
        tb[0] = b'0' + tools as u8;
    }
    txt(x + 58, y + 64, &tb, ACCENT);
}

fn draw_tools(x: u32, y: u32) {
    txt(x, y, b"Available Tools", ACCENT);
    let tools = crate::agents::tools::list_tools();
    for (i, (name, _)) in tools.iter().take(4).enumerate() {
        let nl = name.iter().position(|&c| c == 0).unwrap_or(16).min(16);
        txt(x, y + 24 + i as u32 * 18, &name[..nl], WHITE);
    }
    if tools.len() > 4 {
        txt(x, y + 96, b"...", DIM);
    }
}
