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

use super::state::selected;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rounded_rect;

const CARD: u32 = 0xFF14141C;
const ACCENT: u32 = 0xFF00D4FF;
const DIM: u32 = 0xFF606068;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    let agents = crate::agents::registry::list_agents();
    if agents.is_empty() {
        draw_empty(x, y, w, h);
        return;
    }
    let mut cy = y + 20;
    for (id, name) in agents.iter().take(8) {
        if cy + 60 > y + h {
            break;
        }
        draw_agent_card(x + 20, cy, w - 40, *id, name, selected() == *id);
        cy += 70;
    }
}

fn draw_agent_card(x: u32, y: u32, w: u32, id: u32, name: &[u8; 32], sel: bool) {
    let bg = if sel { 0xFF1E1E28 } else { CARD };
    fill_rounded_rect(x, y, w, 60, 8, bg);
    let len = name.iter().position(|&c| c == 0).unwrap_or(32);
    txt(x + 16, y + 12, &name[..len], 0xFFFFFFFF);
    txt(x + 16, y + 34, b"ID:", DIM);
    let mut buf = [0u8; 8];
    let dlen = fmt_num(id, &mut buf);
    txt(x + 40, y + 34, &buf[..dlen], ACCENT);
    fill_rounded_rect(x + w - 80, y + 15, 60, 30, 6, ACCENT);
    txt(x + w - 68, y + 22, b"Chat", 0xFF000000);
}

fn draw_empty(x: u32, y: u32, w: u32, h: u32) {
    let cx = x + w / 2;
    let cy = y + h / 2;
    fill_rounded_rect(cx - 100, cy - 50, 200, 100, 8, CARD);
    txt(cx - 64, cy - 20, b"No Agents Yet", 0xFFFFFFFF);
    txt(cx - 80, cy + 10, b"Create one to start", DIM);
}

fn fmt_num(mut n: u32, buf: &mut [u8; 8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut i = 0;
    while n > 0 && i < 8 {
        buf[7 - i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    buf.copy_within(8 - i.., 0);
    i
}
