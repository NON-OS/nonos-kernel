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

use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::graphics::window::draw_string;
use super::state::{get_view, WalletView, WALLET_STATE};
use super::types::truncate_address;
use super::render::*;

pub(super) fn draw_sidebar(x: u32, y: u32, h: u32) {
    draw_gradient_bg(x, y, SIDEBAR_WIDTH, h);
    draw_glass_border(x + SIDEBAR_WIDTH - 1, y, 1, h);
    draw_logo(x + 24, y + 28);
    let current = get_view();
    let items: &[(&[u8], WalletView, u32)] = &[
        (b"Overview", WalletView::Overview, COLOR_ACCENT),
        (b"Send", WalletView::Send, COLOR_YELLOW),
        (b"Receive", WalletView::Receive, COLOR_GREEN),
        (b"Staking", WalletView::Staking, COLOR_PURPLE),
        (b"ZkSync L2", WalletView::ZkSync, COLOR_CYAN),
        (b"History", WalletView::Transactions, COLOR_ACCENT_GLOW),
        (b"Stealth", WalletView::Stealth, COLOR_PURPLE_GLOW),
        (b"Settings", WalletView::Settings, COLOR_TEXT_DIM),
    ];
    for (i, (label, view, icon_color)) in items.iter().enumerate() {
        let item_y = y + 90 + (i as u32) * 52;
        if *view == current {
            draw_selected_item(x + 14, item_y, SIDEBAR_WIDTH - 28, 44, *icon_color);
        }
        draw_nav_icon(x + 26, item_y + 10, i, *icon_color, *view == current);
        draw_string(x + 58, item_y + 16, label, if *view == current { COLOR_TEXT_WHITE } else { COLOR_TEXT_SECONDARY });
    }
    draw_account_card(x, y, h);
}

fn draw_gradient_bg(x: u32, y: u32, w: u32, h: u32) {
    for row in 0..h {
        let progress = row as f32 / h as f32;
        let r = lerp(0x12, 0x0A, progress);
        let g = lerp(0x12, 0x0A, progress);
        let b = lerp(0x1A, 0x12, progress);
        let color = 0xFF000000 | (r << 16) | (g << 8) | b;
        fill_rect(x, y + row, w, 1, color);
    }
}

fn draw_glass_border(x: u32, y: u32, w: u32, h: u32) {
    for row in 0..h {
        let glow = ((row as f32 / h as f32) * 30.0) as u32;
        let color = 0xFF000000 | ((0x2A + glow) << 16) | ((0x2A + glow) << 8) | (0x35 + glow);
        fill_rect(x, y + row, w, 1, color);
    }
}

fn draw_logo(x: u32, y: u32) {
    for i in 0..3 { fill_rect(x + i, y + i, 100 - i * 2, 1, blend_alpha(COLOR_ACCENT, 60 - i * 15)); }
    draw_string(x, y + 6, b"N\xd8NOS", COLOR_ACCENT);
    draw_string(x + 52, y + 6, b"Wallet", COLOR_TEXT_WHITE);
    for i in 0..3 { fill_rect(x + i, y + 26 + i, 100 - i * 2, 1, blend_alpha(COLOR_ACCENT, 60 - i * 15)); }
}

fn draw_selected_item(x: u32, y: u32, w: u32, h: u32, accent: u32) {
    let r = 10u32;
    let bg = blend_colors(COLOR_SIDEBAR_HOVER, accent, 30);
    fill_rect(x + r, y, w - 2 * r, h, bg);
    fill_rect(x, y + r, w, h - 2 * r, bg);
    for dy in 0..r { for dx in 0..r { if dx * dx + dy * dy <= r * r {
        put_pixel(x + r - dx, y + r - dy, bg);
        put_pixel(x + w - r + dx - 1, y + r - dy, bg);
        put_pixel(x + r - dx, y + h - r + dy - 1, bg);
        put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, bg);
    }}}
    fill_rect(x, y + 8, 3, h - 16, accent);
    for i in 0..3 { put_pixel(x, y + 8 - 1 + i, blend_alpha(accent, 80 - i * 25)); put_pixel(x, y + h - 8 + i, blend_alpha(accent, 80 - i * 25)); }
}

fn draw_nav_icon(x: u32, y: u32, idx: usize, color: u32, active: bool) {
    let bg = if active { blend_alpha(color, 30) } else { COLOR_CARD };
    draw_rounded_icon_bg(x, y, 28, 28, 8, bg);
    if active { draw_icon_glow(x, y, 28, 28, color); }
    let icon_color = if active { color } else { blend_alpha(color, 70) };
    draw_icon_glyph(x, y, idx, icon_color);
}

fn draw_rounded_icon_bg(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r { for dx in 0..r { if dx * dx + dy * dy <= r * r {
        put_pixel(x + r - dx, y + r - dy, color);
        put_pixel(x + w - r + dx - 1, y + r - dy, color);
        put_pixel(x + r - dx, y + h - r + dy - 1, color);
        put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
    }}}
}

fn draw_icon_glow(x: u32, y: u32, w: u32, h: u32, color: u32) {
    for i in 1..4 { draw_glow_ring(x.saturating_sub(i), y.saturating_sub(i), w + i * 2, h + i * 2, blend_alpha(color, 20 - i * 5)); }
}

fn draw_glow_ring(x: u32, y: u32, w: u32, h: u32, color: u32) {
    fill_rect(x, y, w, 1, color); fill_rect(x, y + h - 1, w, 1, color);
    fill_rect(x, y, 1, h, color); fill_rect(x + w - 1, y, 1, h, color);
}

fn draw_account_card(x: u32, y: u32, h: u32) {
    let card_y = y + h - 95;
    for i in 0..6 { draw_rounded_icon_bg(x + 14 + i / 2, card_y + 4 + i, SIDEBAR_WIDTH - 28, 75, 12, blend_alpha(0x000000, 25 - i * 4)); }
    draw_rounded_icon_bg(x + 14, card_y, SIDEBAR_WIDTH - 28, 75, 12, COLOR_CARD_ELEVATED);
    draw_card_gradient(x + 14, card_y, SIDEBAR_WIDTH - 28, 75, 12);
    let addr_short = { let state = WALLET_STATE.lock(); state.get_active_account().map(|a| truncate_address(&a.address_hex())) };
    if let Some(addr) = addr_short {
        draw_string(x + 26, card_y + 14, b"Active Account", COLOR_TEXT_DIM);
        fill_rect(x + 26, card_y + 32, 8, 8, COLOR_GREEN);
        draw_string(x + 40, card_y + 30, b"Connected", COLOR_GREEN);
        draw_string(x + 26, card_y + 50, &addr, COLOR_TEXT_WHITE);
    }
}

fn draw_card_gradient(x: u32, y: u32, w: u32, h: u32, r: u32) {
    for row in 0..core::cmp::min(h / 3, 20) {
        let alpha = 15 - (row as u32 * 15 / 20);
        let in_radius = row < r;
        let start_x = if in_radius { x + r - isqrt(r * r - (r - row) * (r - row)) } else { x };
        let end_x = if in_radius { x + w - r + isqrt(r * r - (r - row) * (r - row)) } else { x + w };
        if end_x > start_x { fill_rect(start_x, y + row, end_x - start_x, 1, blend_alpha(COLOR_ACCENT, alpha as u32)); }
    }
}

fn draw_icon_glyph(x: u32, y: u32, idx: usize, color: u32) {
    let glyphs: [&[u8]; 8] = [b"\x7f", b"\x1a", b"\x19", b"\x24", b"\x1d", b"\x0f", b"\x2a", b"\x2e"];
    if idx < 8 { crate::graphics::font::draw_char(x + 10, y + 6, glyphs[idx][0], color); }
}

fn lerp(a: u32, b: u32, t: f32) -> u32 { (a as f32 + (b as f32 - a as f32) * t) as u32 }
fn blend_alpha(color: u32, alpha: u32) -> u32 { let a = (alpha * 255 / 100).min(255); (a << 24) | (color & 0x00FFFFFF) }
fn blend_colors(base: u32, overlay: u32, amount: u32) -> u32 {
    let br = (base >> 16) & 0xFF; let bg = (base >> 8) & 0xFF; let bb = base & 0xFF;
    let or = (overlay >> 16) & 0xFF; let og = (overlay >> 8) & 0xFF; let ob = overlay & 0xFF;
    let r = br + (or - br) * amount / 100; let g = bg + (og - bg) * amount / 100; let b = bb + (ob - bb) * amount / 100;
    0xFF000000 | (r << 16) | (g << 8) | b
}
fn isqrt(n: u32) -> u32 { if n == 0 { return 0; } let mut x = n; let mut y = (x + 1) / 2; while y < x { x = y; y = (x + n / x) / 2; } x }
