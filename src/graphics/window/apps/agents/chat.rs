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

use super::state::*;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};

const CARD: u32 = 0xFF14141C;
const INPUT_BG: u32 = 0xFF1E1E28;
const ACCENT: u32 = 0xFF00D4FF;
const DIM: u32 = 0xFF606068;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    txt(x + 20, y + 10, b"< Back", DIM);
    let agent = crate::agents::registry::get_agent(selected());
    if let Some(a) = agent {
        txt(x + 80, y + 10, a.name(), 0xFFFFFFFF);
        draw_messages(x + 20, y + 40, w - 40, h - 100, &a);
    }
    draw_input(x + 20, y + h - 50, w - 40);
}

fn draw_messages(x: u32, y: u32, w: u32, h: u32, agent: &crate::agents::Agent) {
    fill_rounded_rect(x, y, w, h, 8, CARD);
    let mut cy = y + 10;
    for msg in agent.messages.iter().take(20) {
        if cy + 30 > y + h {
            break;
        }
        let role: &[u8] = match msg.role {
            crate::agents::core::MessageRole::User => b"You: ",
            crate::agents::core::MessageRole::Assistant => b"AI: ",
            _ => b"",
        };
        txt(x + 10, cy, role, ACCENT);
        let content_len = msg.content.len().min(60);
        txt(x + 10 + role.len() as u32 * 8, cy, &msg.content[..content_len], 0xFFFFFFFF);
        cy += 20;
    }
    if agent.messages.is_empty() {
        txt(x + 10, cy, b"Start chatting with your agent", DIM);
    }
}

fn draw_input(x: u32, y: u32, w: u32) {
    let bg = if input_focused() { INPUT_BG } else { CARD };
    fill_rounded_rect(x, y, w - 70, 36, 6, bg);
    let len = input_len();
    unsafe {
        for i in 0..len.min(50) {
            draw_char(x + 10 + i as u32 * 8, y + 10, INPUT_BUF[i], 0xFFFFFFFF);
        }
    }
    if input_focused() {
        fill_rect(x + 10 + len as u32 * 8, y + 8, 2, 20, ACCENT);
    }
    fill_rounded_rect(x + w - 60, y, 60, 36, 6, ACCENT);
    txt(x + w - 48, y + 10, b"Send", 0xFF000000);
}

pub(crate) use super::chat_input::{handle_click, handle_key};
