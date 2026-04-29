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

use super::results::{search, ResultCategory};
use super::state::{get_query, get_selected, is_open};
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};

const WIDTH: u32 = 600;
const INPUT_H: u32 = 56;
const RESULT_H: u32 = 44;
const MAX_RESULTS: usize = 8;
const BG: u32 = 0xF0181820;
const INPUT_BG: u32 = 0xFF1C1C24;
const SELECTED_BG: u32 = 0xFF2A3A4A;
const TEXT: u32 = 0xFFE5E5E7;
const TEXT_DIM: u32 = 0xFF8888A0;
const ACCENT: u32 = 0xFF00D4FF;

pub fn draw(sw: u32, _sh: u32) {
    if !is_open() {
        return;
    }
    let (query, q_len) = get_query();
    let results: heapless::Vec<_, 8> = search(&query[..q_len]).take(MAX_RESULTS).collect();
    let result_count = results.len();
    let total_h = INPUT_H + result_count as u32 * RESULT_H + 16;
    let x = (sw - WIDTH) / 2;
    let y = 120u32;
    fill_rounded_rect(x, y, WIDTH, total_h, 12, BG);
    draw_input(x, y, &query, q_len);
    let selected = get_selected();
    for (i, result) in results.iter().enumerate() {
        draw_result(x, y + INPUT_H + i as u32 * RESULT_H, result, i == selected);
    }
}

fn draw_input(x: u32, y: u32, query: &[u8], len: usize) {
    fill_rounded_rect(x + 12, y + 12, WIDTH - 24, 40, 8, INPUT_BG);
    draw_text(x + 24, y + 22, b"\x10", ACCENT);
    if len > 0 {
        draw_text(x + 44, y + 22, &query[..len], TEXT);
    } else {
        draw_text(x + 44, y + 22, b"Search...", TEXT_DIM);
    }
    let cursor_x = x + 44 + len as u32 * 8;
    fill_rect(cursor_x, y + 20, 2, 16, ACCENT);
}

fn draw_result(x: u32, y: u32, result: &super::results::SearchResult, selected: bool) {
    if selected {
        fill_rounded_rect(x + 8, y + 2, WIDTH - 16, RESULT_H - 4, 6, SELECTED_BG);
    }
    let icon = category_icon(result.category);
    draw_text(x + 20, y + 14, icon, ACCENT);
    draw_text(x + 48, y + 14, result.name, TEXT);
    let cat = category_label(result.category);
    draw_text(x + WIDTH - 120, y + 14, cat, TEXT_DIM);
}

fn category_icon(cat: ResultCategory) -> &'static [u8] {
    match cat {
        ResultCategory::Application => b"@",
        ResultCategory::Setting => b"*",
        ResultCategory::File => b"#",
        ResultCategory::Command => b">",
    }
}

fn category_label(cat: ResultCategory) -> &'static [u8] {
    match cat {
        ResultCategory::Application => b"App",
        ResultCategory::Setting => b"Setting",
        ResultCategory::File => b"File",
        ResultCategory::Command => b"Command",
    }
}
