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

use super::constants::*;
use super::content_row::{draw_rename_input, draw_size_column};
use super::icons;
use super::state::{
    get_input_text, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_CREATING_FILE, FM_CREATING_FOLDER,
    FM_RENAMING, FM_SELECTED_ITEM,
};
use super::types::FileEntry;
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::*;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

pub fn draw(x: u32, y: u32, w: u32, h: u32) {
    let list_y = y + HEADER_HEIGHT + LIST_HEADER_HEIGHT;
    let list_h = h - HEADER_HEIGHT - LIST_HEADER_HEIGHT - STATUS_BAR_HEIGHT;
    fill_rect(x, list_y, w, list_h, BG_APP);

    let max_rows = (list_h / ROW_HEIGHT) as u8;
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    let creating_folder = FM_CREATING_FOLDER.load(Ordering::Relaxed);
    let creating_file = FM_CREATING_FILE.load(Ordering::Relaxed);
    let creating = creating_folder || creating_file;

    if creating {
        draw_create_row(x, list_y, w, creating_folder);
    }

    let offset = if creating { 1 } else { 0 };
    let count = FILE_ENTRY_COUNT.load(Ordering::Relaxed);

    for i in 0..count.min(max_rows.saturating_sub(offset)) {
        let entry = unsafe { &FILE_ENTRIES[i as usize] };
        let ry = list_y + ((i + offset) as u32) * ROW_HEIGHT;
        draw_file_row(x, ry, w, entry, i, selected);
    }
}

fn draw_create_row(x: u32, y: u32, w: u32, is_folder: bool) {
    primitives::rounded_rect(x + 4, y + 2, w - 8, ROW_HEIGHT - 4, 4, BG_SELECTED);
    if is_folder {
        icons::folder(x + 12, y + 6, ACCENT);
    } else {
        icons::file(x + 12, y + 5, TEXT_SECONDARY);
    }
    primitives::rounded_rect(x + 40, y + 4, 200, ROW_HEIGHT - 8, 4, BG_INPUT);
    let input_text = get_input_text();
    text::draw(x + 48, y + 10, input_text.as_bytes(), TEXT_PRIMARY);
    let cursor_x = x + 48 + (input_text.len() as u32) * 8;
    fill_rect(cursor_x, y + 8, 2, 16, ACCENT);
}

fn draw_file_row(x: u32, ry: u32, w: u32, entry: &FileEntry, i: u8, selected: u8) {
    if i == selected {
        primitives::rounded_rect(x + 4, ry + 2, w - 8, ROW_HEIGHT - 4, 4, BG_SELECTED);
    } else if i % 2 == 1 {
        fill_rect(x, ry, w, ROW_HEIGHT, BG_SURFACE);
    }

    if entry.is_dir {
        icons::folder(x + 12, ry + 6, ACCENT);
    } else {
        icons::file(x + 12, ry + 5, TEXT_SECONDARY);
    }

    if i == selected && FM_RENAMING.load(Ordering::Relaxed) {
        draw_rename_input(x, ry);
    } else {
        text::draw(x + 40, ry + 10, &entry.name[..entry.name_len as usize], TEXT_PRIMARY);
    }

    draw_size_column(x, ry, w, entry);
}
