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

use super::entries::{get_entry, get_entry_count};
use super::path::{get_filename, get_path};
use super::state::{get_mode, is_open, DialogMode};
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::{ACCENT, TEXT_PRIMARY, TEXT_SECONDARY};
use crate::display::framebuffer::dimensions;
use core::sync::atomic::{AtomicUsize, Ordering};

const DIALOG_W: u32 = 500;
const DIALOG_H: u32 = 400;
const BG: u32 = 0xF0181820;
const ITEM_H: u32 = 32;

static SELECTED_IDX: AtomicUsize = AtomicUsize::new(0);
static SCROLL_OFFSET: AtomicUsize = AtomicUsize::new(0);

pub fn draw() {
    if !is_open() {
        return;
    }
    let (sw, sh) = dimensions();
    let x = (sw - DIALOG_W) / 2;
    let y = (sh - DIALOG_H) / 2;
    primitives::rounded_rect(x, y, DIALOG_W, DIALOG_H, 12, BG);
    draw_header(x, y);
    draw_path_bar(x, y + 40);
    draw_file_list(x, y + 80);
    if get_mode() == DialogMode::Save {
        draw_filename_input(x, y + DIALOG_H - 80);
    }
    draw_buttons(x, y + DIALOG_H - 44);
}

fn draw_header(x: u32, y: u32) {
    let title = match get_mode() {
        DialogMode::Open => b"Open File",
        DialogMode::Save => b"Save File",
    };
    text::draw(x + 20, y + 12, title, TEXT_PRIMARY);
    text::draw(x + DIALOG_W - 30, y + 10, b"x", TEXT_SECONDARY);
}

fn draw_path_bar(x: u32, y: u32) {
    primitives::rounded_rect(x + 12, y, DIALOG_W - 24, 32, 6, 0xFF1C1C24);
    let path = get_path();
    text::draw(x + 20, y + 8, path, TEXT_SECONDARY);
}

fn draw_file_list(x: u32, y: u32) {
    let list_h = if get_mode() == DialogMode::Save { 200 } else { 260 };
    primitives::rounded_rect(x + 12, y, DIALOG_W - 24, list_h, 6, 0xFF1C1C24);
    let count = get_entry_count();
    let selected = SELECTED_IDX.load(Ordering::Relaxed);
    let offset = SCROLL_OFFSET.load(Ordering::Relaxed);
    let visible = (list_h / ITEM_H) as usize;
    for i in 0..visible {
        let idx = offset + i;
        if idx >= count {
            break;
        }
        let ey = y + 4 + i as u32 * ITEM_H;
        draw_entry(x + 16, ey, idx, idx == selected);
    }
}

fn draw_entry(x: u32, y: u32, idx: usize, selected: bool) {
    if let Some(entry) = get_entry(idx) {
        if selected {
            primitives::rounded_rect(x - 4, y, DIALOG_W - 40, ITEM_H - 2, 4, 0xFF2A3A4A);
        }
        let icon = if entry.is_dir { b"[D]" } else { b"[F]" };
        let color = if entry.is_dir { ACCENT } else { TEXT_PRIMARY };
        text::draw(x, y + 6, icon, color);
        text::draw(x + 32, y + 6, &entry.name[..entry.name_len], TEXT_PRIMARY);
    }
}

fn draw_filename_input(x: u32, y: u32) {
    text::draw(x + 16, y, b"Filename:", TEXT_SECONDARY);
    primitives::rounded_rect(x + 12, y + 20, DIALOG_W - 24, 32, 6, 0xFF1C1C24);
    let filename = get_filename();
    text::draw(x + 20, y + 28, filename, TEXT_PRIMARY);
    let cursor_x = x + 20 + filename.len() as u32 * 8;
    primitives::rect(cursor_x, y + 24, 2, 20, ACCENT);
}

fn draw_buttons(x: u32, y: u32) {
    primitives::rounded_rect(x + DIALOG_W - 180, y, 80, 32, 6, 0xFF333340);
    text::draw(x + DIALOG_W - 160, y + 8, b"Cancel", TEXT_SECONDARY);
    let action = match get_mode() {
        DialogMode::Open => b"Open",
        DialogMode::Save => b"Save",
    };
    primitives::rounded_rect(x + DIALOG_W - 92, y, 80, 32, 6, ACCENT);
    text::draw(x + DIALOG_W - 72, y + 8, action, 0xFF101018);
}

pub(super) fn get_selected() -> usize {
    SELECTED_IDX.load(Ordering::Relaxed)
}

pub(super) fn select_next() {
    let count = get_entry_count();
    let cur = SELECTED_IDX.load(Ordering::Relaxed);
    SELECTED_IDX.store((cur + 1).min(count.saturating_sub(1)), Ordering::Relaxed);
}

pub(super) fn select_prev() {
    let cur = SELECTED_IDX.load(Ordering::Relaxed);
    SELECTED_IDX.store(cur.saturating_sub(1), Ordering::Relaxed);
}
