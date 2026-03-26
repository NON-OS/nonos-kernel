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

extern crate alloc;

use alloc::string::{String, ToString};
use core::sync::atomic::Ordering;

use super::state::{self, EcosystemTab};
use super::tabs;
use super::render_helpers::{
    draw_border, draw_string, draw_spinner, draw_error_toast,
    COLOR_CARD_BG, COLOR_CARD_BORDER, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_BRIGHT,
    COLOR_ACCENT, COLOR_WARNING, COLOR_INPUT_BG, COLOR_INPUT_BORDER,
};
use super::render_tabs::{
    draw_wallet_tab, draw_staking_tab, draw_lp_tab, draw_node_tab, draw_privacy_tab,
};
use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::graphics::font::draw_char;
use crate::apps::ecosystem::browser::engine::RenderContent;

const COLOR_BG: u32 = 0xFF000000;
const COLOR_URL_BAR: u32 = 0xFF2C2C2E;
const COLOR_URL_TEXT: u32 = 0xFFFFFFFF;

pub fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);

    let active_tab = state::get_active_tab();
    tabs::draw_tab_bar(x, y, w, active_tab);

    let content_y = y + tabs::TAB_HEIGHT;
    let content_h = h.saturating_sub(tabs::TAB_HEIGHT);

    match active_tab {
        EcosystemTab::Browser => draw_browser_tab(x, content_y, w, content_h),
        EcosystemTab::Wallet => draw_wallet_tab(x, content_y, w, content_h),
        EcosystemTab::Staking => draw_staking_tab(x, content_y, w, content_h),
        EcosystemTab::Liquidity => draw_lp_tab(x, content_y, w, content_h),
        EcosystemTab::Node => draw_node_tab(x, content_y, w, content_h),
        EcosystemTab::Privacy => draw_privacy_tab(x, content_y, w, content_h),
    }

    if let Some(error) = state::get_error() {
        draw_error_toast(x, y + h - 60, w, &error);
    }
}

const COLOR_LINK: u32 = 0xFF00BFFF;
const COLOR_HEADING: u32 = 0xFF00FFCC;
const COLOR_SCROLLBAR: u32 = 0xFF48484A;
const COLOR_SCROLLBAR_THUMB: u32 = 0xFF00FFCC;

fn draw_browser_tab(x: u32, y: u32, w: u32, h: u32) {
    draw_url_bar(x + 8, y + 8, w - 16, 36);

    let content_y = y + 52;
    let content_h = h.saturating_sub(60);

    fill_rect(x + 8, content_y, w - 16, content_h, COLOR_CARD_BG);
    draw_border(x + 8, content_y, w - 16, content_h, COLOR_CARD_BORDER);

    let loading = state::LOADING.load(Ordering::Relaxed);
    if loading {
        draw_string(x + 20, content_y + 20, b"Loading...", COLOR_TEXT_DIM);
        draw_spinner(x + w / 2 - 16, content_y + content_h / 2 - 16);
    } else {
        let render = state::PAGE_RENDER.lock();
        let scroll = state::PAGE_SCROLL.load(Ordering::Relaxed);
        let total_lines = state::PAGE_TOTAL_LINES.load(Ordering::Relaxed);
        let visible_lines = (content_h.saturating_sub(16) / 20) as usize;

        if let Some(ref output) = *render {
            if output.lines.is_empty() {
                draw_empty_browser_help(x, content_y);
            } else {
                let clip_bottom = content_y + content_h - 4;
                for render_line in output.lines.iter().skip(scroll).take(visible_lines) {
                    let line_y = content_y + 8 + render_line.y.saturating_sub(
                        output.lines.get(scroll).map(|l| l.y).unwrap_or(0)
                    );
                    if line_y >= clip_bottom {
                        break;
                    }
                    for elem in &render_line.elements {
                        draw_render_element(x + 8, line_y, elem, w - 32, clip_bottom);
                    }
                }

                if total_lines > visible_lines {
                    draw_scrollbar(x + w - 24, content_y + 4, 8, content_h - 8, scroll, total_lines, visible_lines);
                }

                if let Some(title) = state::get_page_title() {
                    let title_bytes = title.as_bytes();
                    let max_title = ((w - 100) / 8) as usize;
                    let display_len = title_bytes.len().min(max_title);
                    draw_string(x + 16, content_y + content_h - 20, &title_bytes[..display_len], COLOR_TEXT_DIM);
                }
            }
        } else {
            draw_empty_browser_help(x, content_y);
        }
    }
}

fn draw_empty_browser_help(x: u32, content_y: u32) {
    draw_string(x + 20, content_y + 20, b"Enter a URL to browse the web", COLOR_TEXT_DIM);
    draw_string(x + 20, content_y + 44, b"Privacy features enabled:", COLOR_TEXT);
    draw_string(x + 20, content_y + 68, b"  - Tracker blocking", COLOR_ACCENT);
    draw_string(x + 20, content_y + 92, b"  - URL parameter stripping", COLOR_ACCENT);
    draw_string(x + 20, content_y + 116, b"  - JavaScript disabled by default", COLOR_ACCENT);
    draw_string(x + 20, content_y + 156, b"Keyboard shortcuts:", COLOR_TEXT);
    draw_string(x + 20, content_y + 180, b"  Page Up/Down - Scroll page", COLOR_TEXT_DIM);
    draw_string(x + 20, content_y + 204, b"  Enter - Navigate to URL", COLOR_TEXT_DIM);
}

fn draw_render_element(
    base_x: u32,
    line_y: u32,
    elem: &crate::apps::ecosystem::browser::engine::RenderElement,
    max_width: u32,
    clip_bottom: u32,
) {
    let ex = base_x + elem.x;
    if ex >= base_x + max_width {
        return;
    }

    match &elem.content {
        RenderContent::Text { ref text, style } => {
            let fg = style.color.unwrap_or(
                if style.heading_level > 0 {
                    COLOR_HEADING
                } else if style.bold {
                    COLOR_TEXT_BRIGHT
                } else {
                    COLOR_TEXT
                }
            );

            // Background color for code blocks or styled elements
            if let Some(bg) = style.bg_color {
                let text_w = (text.len() as u32) * 8;
                fill_rect(ex, line_y, text_w.min(max_width), 16, bg);
            }

            // Draw italic indicator (slight x offset for visual cue)
            let italic_offset: u32 = if style.italic { 1 } else { 0 };

            let mut cx = ex;
            for &ch in text.as_bytes() {
                if cx + 8 > base_x + max_width {
                    break;
                }
                draw_char(cx + italic_offset, line_y, ch, fg);
                cx += 8;
            }

            // Underline
            if style.underline && cx > ex {
                let uy = line_y + 15;
                if uy < clip_bottom {
                    fill_rect(ex, uy, cx - ex, 1, fg);
                }
            }
        }

        RenderContent::Link { ref text, ref href } => {
            let _ = href;
            let mut cx = ex;
            for &ch in text.as_bytes() {
                if cx + 8 > base_x + max_width {
                    break;
                }
                draw_char(cx, line_y, ch, COLOR_LINK);
                cx += 8;
            }
            // Underline for links
            if cx > ex {
                let uy = line_y + 15;
                if uy < clip_bottom {
                    fill_rect(ex, uy, cx - ex, 1, COLOR_LINK);
                }
            }
        }

        RenderContent::Image { ref alt, width, height } => {
            let iw = (*width).min(max_width);
            let ih = *height;
            // Draw placeholder box
            fill_rect(ex, line_y, iw, ih.min(200), 0xFF1C1C1E);
            draw_border_thin(ex, line_y, iw, ih.min(200), COLOR_TEXT_DIM);
            // Draw alt text inside
            let mut cx = ex + 4;
            for &ch in alt.as_bytes() {
                if cx + 8 > ex + iw {
                    break;
                }
                draw_char(cx, line_y + 2, ch, COLOR_TEXT_DIM);
                cx += 8;
            }
        }

        RenderContent::DecodedImage { ref data } => {
            blit_image_data(ex, line_y, data, max_width, clip_bottom);
        }

        RenderContent::Canvas { ref data } => {
            blit_image_data(ex, line_y, data, max_width, clip_bottom);
        }

        RenderContent::Svg { ref data } => {
            blit_image_data(ex, line_y, data, max_width, clip_bottom);
        }

        RenderContent::Input { ref name, width } => {
            let iw = (*width).min(max_width);
            fill_rect(ex, line_y, iw, 20, COLOR_INPUT_BG);
            draw_border_thin(ex, line_y, iw, 20, COLOR_INPUT_BORDER);
            let mut cx = ex + 4;
            for &ch in name.as_bytes() {
                if cx + 8 > ex + iw {
                    break;
                }
                draw_char(cx, line_y + 2, ch, COLOR_WARNING);
                cx += 8;
            }
        }

        RenderContent::Button { ref text } => {
            let bw = (text.len() as u32 * 8 + 16).min(max_width);
            fill_rect(ex, line_y, bw, 20, 0xFF2C2C4E);
            draw_border_thin(ex, line_y, bw, 20, COLOR_ACCENT);
            let mut cx = ex + 8;
            for &ch in text.as_bytes() {
                if cx + 8 > ex + bw {
                    break;
                }
                draw_char(cx, line_y + 2, ch, COLOR_ACCENT);
                cx += 8;
            }
        }

        RenderContent::Select { ref name, ref value } => {
            let label = if value.is_empty() { name } else { value };
            let sw = ((label.len() as u32 + 4) * 8).min(max_width);
            fill_rect(ex, line_y, sw, 20, COLOR_INPUT_BG);
            draw_border_thin(ex, line_y, sw, 20, COLOR_INPUT_BORDER);
            let mut cx = ex + 4;
            for &ch in label.as_bytes() {
                if cx + 8 > ex + sw - 16 { break; }
                draw_char(cx, line_y + 2, ch, COLOR_TEXT);
                cx += 8;
            }
            // Draw dropdown arrow
            let arrow_x = ex + sw - 12;
            draw_char(arrow_x, line_y + 2, b'v', COLOR_TEXT_DIM);
        }

        RenderContent::Textarea { ref name, width, height } => {
            let tw = (*width).min(max_width);
            let th = (*height).min(200);
            fill_rect(ex, line_y, tw, th, COLOR_INPUT_BG);
            draw_border_thin(ex, line_y, tw, th, COLOR_INPUT_BORDER);
            let mut cx = ex + 4;
            for &ch in name.as_bytes() {
                if cx + 8 > ex + tw { break; }
                draw_char(cx, line_y + 2, ch, COLOR_TEXT_DIM);
                cx += 8;
            }
        }

        RenderContent::HorizontalRule => {
            let rule_w = max_width.saturating_sub(20);
            fill_rect(ex, line_y + 8, rule_w, 1, COLOR_TEXT_DIM);
        }

        RenderContent::LineBreak => {}
    }
}

/// Blit ARGB8888 pixel data from an ImageData to the framebuffer.
fn blit_image_data(
    x: u32,
    y: u32,
    data: &crate::apps::ecosystem::browser::engine::ImageData,
    max_width: u32,
    clip_bottom: u32,
) {
    let draw_w = data.width.min(max_width);
    for py in 0..data.height {
        let screen_y = y + py;
        if screen_y >= clip_bottom {
            break;
        }
        for px in 0..draw_w {
            let idx = (py * data.width + px) as usize;
            if idx < data.pixels.len() {
                let color = data.pixels[idx];
                // Skip transparent pixels (alpha == 0)
                if color & 0xFF000000 != 0 {
                    put_pixel(x + px, screen_y, color);
                }
            }
        }
    }
}

/// Thin 1px border helper.
fn draw_border_thin(x: u32, y: u32, w: u32, h: u32, color: u32) {
    fill_rect(x, y, w, 1, color);
    fill_rect(x, y + h - 1, w, 1, color);
    fill_rect(x, y, 1, h, color);
    fill_rect(x + w - 1, y, 1, h, color);
}

fn draw_scrollbar(x: u32, y: u32, w: u32, h: u32, scroll: usize, total: usize, visible: usize) {
    fill_rect(x, y, w, h, COLOR_SCROLLBAR);

    if total > 0 {
        let thumb_h = ((visible as u32 * h) / total as u32).max(20).min(h);
        let thumb_y = if total > visible {
            y + ((scroll as u32 * (h - thumb_h)) / (total - visible) as u32)
        } else {
            y
        };
        fill_rect(x, thumb_y, w, thumb_h, COLOR_SCROLLBAR_THUMB);
    }
}

fn draw_url_bar(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_URL_BAR);
    draw_border(x, y, w, h, COLOR_CARD_BORDER);

    let nav_btn_w = 28;
    draw_nav_button(x + 4, y + 4, nav_btn_w, h - 8, b"<");
    draw_nav_button(x + 4 + nav_btn_w + 4, y + 4, nav_btn_w, h - 8, b">");
    draw_nav_button(x + 4 + (nav_btn_w + 4) * 2, y + 4, nav_btn_w, h - 8, b"R");

    let url_x = x + 4 + (nav_btn_w + 4) * 3 + 8;
    let url_w = w - (url_x - x) - 8;

    let url_focused = state::URL_FOCUSED.load(Ordering::Relaxed);
    let is_https = state::IS_HTTPS.load(Ordering::Relaxed);
    let border_color = if url_focused { COLOR_ACCENT } else { COLOR_INPUT_BORDER };

    fill_rect(url_x, y + 4, url_w, h - 8, COLOR_INPUT_BG);
    draw_border(url_x, y + 4, url_w, h - 8, border_color);

    let lock_x = url_x + 6;
    let text_start = if is_https { url_x + 22 } else { url_x + 8 };

    if is_https {
        draw_char(lock_x, y + 12, 0xE2, COLOR_ACCENT);
        draw_char(lock_x + 8, y + 12, b'S', COLOR_ACCENT);
    }

    let url_buf = state::URL_BUFFER.lock();
    let url_len = state::URL_LEN.load(Ordering::Relaxed);
    let url_cursor = state::URL_CURSOR.load(Ordering::Relaxed);

    let available_w = url_w - (text_start - url_x) - 8;
    if url_len > 0 {
        let max_chars = (available_w / 8) as usize;
        let display_len = url_len.min(max_chars);
        for (i, &ch) in url_buf[..display_len].iter().enumerate() {
            draw_char(text_start + i as u32 * 8, y + 12, ch, COLOR_URL_TEXT);
        }
    } else {
        draw_string(text_start, y + 12, b"Enter URL...", COLOR_TEXT_DIM);
    }

    if url_focused {
        let cursor_x = text_start + (url_cursor as u32) * 8;
        fill_rect(cursor_x, y + 8, 2, h - 16, COLOR_TEXT_BRIGHT);
    }
}

fn draw_nav_button(x: u32, y: u32, w: u32, h: u32, label: &[u8]) {
    fill_rect(x, y, w, h, COLOR_CARD_BG);
    let text_x = x + (w.saturating_sub(label.len() as u32 * 8)) / 2;
    let text_y = y + (h.saturating_sub(16)) / 2;
    for (i, &ch) in label.iter().enumerate() {
        draw_char(text_x + i as u32 * 8, text_y, ch, COLOR_TEXT);
    }
}

pub fn format_balance(wei: u128) -> String {
    let eth = wei / 1_000_000_000_000_000_000;
    let gwei = (wei / 1_000_000_000) % 1_000_000_000;
    alloc::format!("{}.{:09}", eth, gwei)
}

pub fn format_status(connected: bool) -> String {
    if connected {
        "Connected".to_string()
    } else {
        "Disconnected".to_string()
    }
}
