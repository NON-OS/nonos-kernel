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

use super::render_elements_input::{
    blit_image_data, draw_button_element, draw_input_element, draw_select_element,
    draw_textarea_element,
};
use super::render_helpers::{COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_DIM};
use super::render_utils::draw_border_thin;
use crate::apps::ecosystem::browser::engine::{RenderContent, RenderElement};
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rect;

const COLOR_LINK: u32 = 0xFF00BFFF;
const COLOR_HEADING: u32 = 0xFF00FFCC;

pub fn draw_render_element(
    base_x: u32,
    line_y: u32,
    elem: &RenderElement,
    max_width: u32,
    clip_bottom: u32,
) {
    let ex = base_x + elem.x;
    if ex >= base_x + max_width {
        return;
    }
    match &elem.content {
        RenderContent::Text { ref text, style } => {
            draw_text(ex, line_y, text, style, max_width, base_x, clip_bottom)
        }
        RenderContent::Link { ref text, .. } => {
            draw_link(ex, line_y, text, max_width, base_x, clip_bottom)
        }
        RenderContent::Image { ref alt, width, height, .. } => {
            draw_image(ex, line_y, alt, *width, *height, max_width)
        }
        RenderContent::DecodedImage { ref data } => {
            blit_image_data(ex, line_y, data, max_width, clip_bottom)
        }
        RenderContent::Canvas { ref data } => {
            blit_image_data(ex, line_y, data, max_width, clip_bottom)
        }
        RenderContent::Svg { ref data } => {
            blit_image_data(ex, line_y, data, max_width, clip_bottom)
        }
        RenderContent::Input { ref name, width } => {
            draw_input_element(ex, line_y, name, *width, max_width)
        }
        RenderContent::Button { ref text } => draw_button_element(ex, line_y, text, max_width),
        RenderContent::Select { ref name, ref value } => {
            draw_select_element(ex, line_y, name, value, max_width)
        }
        RenderContent::Textarea { ref name, width, height } => {
            draw_textarea_element(ex, line_y, name, *width, *height, max_width)
        }
        RenderContent::HorizontalRule => {
            fill_rect(ex, line_y + 8, max_width.saturating_sub(20), 1, COLOR_TEXT_DIM)
        }
        RenderContent::LineBreak => {}
    }
}

fn draw_text(
    ex: u32,
    line_y: u32,
    text: &str,
    style: &crate::apps::ecosystem::browser::engine::TextStyle,
    max_width: u32,
    base_x: u32,
    clip_bottom: u32,
) {
    let fg = style.color.unwrap_or(if style.heading_level > 0 {
        COLOR_HEADING
    } else if style.bold {
        COLOR_TEXT_BRIGHT
    } else {
        COLOR_TEXT
    });
    if let Some(bg) = style.bg_color {
        let text_w = (text.len() as u32) * 8;
        fill_rect(ex, line_y, text_w.min(max_width), 16, bg);
    }
    let italic_offset: u32 = if style.italic { 1 } else { 0 };
    let mut cx = ex;
    for &ch in text.as_bytes() {
        if cx + 8 > base_x + max_width {
            break;
        }
        draw_char(cx + italic_offset, line_y, ch, fg);
        cx += 8;
    }
    if style.underline && cx > ex {
        let uy = line_y + 15;
        if uy < clip_bottom {
            fill_rect(ex, uy, cx - ex, 1, fg);
        }
    }
}

fn draw_link(ex: u32, line_y: u32, text: &str, max_width: u32, base_x: u32, clip_bottom: u32) {
    let mut cx = ex;
    for &ch in text.as_bytes() {
        if cx + 8 > base_x + max_width {
            break;
        }
        draw_char(cx, line_y, ch, COLOR_LINK);
        cx += 8;
    }
    if cx > ex {
        let uy = line_y + 15;
        if uy < clip_bottom {
            fill_rect(ex, uy, cx - ex, 1, COLOR_LINK);
        }
    }
}

fn draw_image(ex: u32, line_y: u32, alt: &str, width: u32, height: u32, max_width: u32) {
    let iw = width.min(max_width);
    let ih = height.min(200);
    fill_rect(ex, line_y, iw, ih, 0xFF1C1C1E);
    draw_border_thin(ex, line_y, iw, ih, COLOR_TEXT_DIM);
    let mut cx = ex + 4;
    for &ch in alt.as_bytes() {
        if cx + 8 > ex + iw {
            break;
        }
        draw_char(cx, line_y + 2, ch, COLOR_TEXT_DIM);
        cx += 8;
    }
}
