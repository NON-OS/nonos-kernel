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

use super::render_browser_help::draw_empty_browser_help;
use super::render_elements::draw_render_element;
use super::render_helpers::{
    draw_border, draw_spinner, draw_string, COLOR_CARD_BG, COLOR_CARD_BORDER, COLOR_TEXT_DIM,
};
use super::render_url_bar::draw_url_bar;
use super::render_utils::draw_scrollbar;
use super::state;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

pub fn draw_browser_tab(x: u32, y: u32, w: u32, h: u32) {
    draw_url_bar(x + 8, y + 8, w - 16, 36);
    let content_y = y + 52;
    let content_h = h.saturating_sub(60);
    fill_rect(x + 8, content_y, w - 16, content_h, COLOR_CARD_BG);
    draw_border(x + 8, content_y, w - 16, content_h, COLOR_CARD_BORDER);
    let loading = state::LOADING.load(Ordering::Relaxed);
    if loading {
        draw_loading_state(x, content_y, w, content_h);
    } else {
        draw_page_content(x, content_y, w, content_h);
    }
}

fn draw_loading_state(x: u32, content_y: u32, w: u32, content_h: u32) {
    draw_string(x + 20, content_y + 20, b"Loading...", COLOR_TEXT_DIM);
    draw_spinner(x + w / 2 - 16, content_y + content_h / 2 - 16);
}

fn draw_page_content(x: u32, content_y: u32, w: u32, content_h: u32) {
    let render = state::PAGE_RENDER.lock();
    let scroll = state::PAGE_SCROLL.load(Ordering::Relaxed);
    let total_lines = state::PAGE_TOTAL_LINES.load(Ordering::Relaxed);
    let visible_lines = (content_h.saturating_sub(16) / 20) as usize;
    if let Some(ref output) = *render {
        if output.lines.is_empty() {
            draw_empty_browser_help(x, content_y);
        } else {
            draw_rendered_lines(x, content_y, w, content_h, output, scroll, visible_lines);
            if total_lines > visible_lines {
                draw_scrollbar(
                    x + w - 24,
                    content_y + 4,
                    8,
                    content_h - 8,
                    scroll,
                    total_lines,
                    visible_lines,
                );
            }
            draw_page_title(x, content_y, w, content_h);
        }
    } else {
        draw_empty_browser_help(x, content_y);
    }
}

fn draw_rendered_lines(
    x: u32,
    content_y: u32,
    w: u32,
    content_h: u32,
    output: &crate::apps::ecosystem::browser::engine::RenderOutput,
    scroll: usize,
    visible_lines: usize,
) {
    let clip_bottom = content_y + content_h - 4;
    for render_line in output.lines.iter().skip(scroll).take(visible_lines) {
        let line_y = content_y
            + 8
            + render_line.y.saturating_sub(output.lines.get(scroll).map(|l| l.y).unwrap_or(0));
        if line_y >= clip_bottom {
            break;
        }
        for elem in &render_line.elements {
            draw_render_element(x + 8, line_y, elem, w - 32, clip_bottom);
        }
    }
}

fn draw_page_title(x: u32, content_y: u32, w: u32, content_h: u32) {
    if let Some(title) = state::get_page_title() {
        let title_bytes = title.as_bytes();
        let max_title = ((w - 100) / 8) as usize;
        let display_len = title_bytes.len().min(max_title);
        draw_string(
            x + 16,
            content_y + content_h - 20,
            &title_bytes[..display_len],
            COLOR_TEXT_DIM,
        );
    }
}
