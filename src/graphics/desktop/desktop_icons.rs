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

use core::sync::atomic::{AtomicU8, Ordering};
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;
use crate::fs::ramfs;
use super::constants::{MENU_BAR_HEIGHT, DOCK_HEIGHT};

const ICON_SIZE: u32 = 48;
const ICON_SPACING: u32 = 80;
const ICON_START_X: u32 = 140;
const ICON_START_Y: u32 = 60;
const MAX_ICONS: usize = 24;
const NAME_LEN: usize = 16;

static ICON_COUNT: AtomicU8 = AtomicU8::new(0);
static mut ICONS: [DesktopIcon; MAX_ICONS] = [DesktopIcon::empty(); MAX_ICONS];

#[derive(Clone, Copy)]
pub(super) struct DesktopIcon { pub name: [u8; NAME_LEN], pub name_len: u8, pub is_dir: bool }

impl DesktopIcon {
    const fn empty() -> Self { Self { name: [0; NAME_LEN], name_len: 0, is_dir: false } }
}

pub(super) fn refresh() {
    let mut count = 0usize;
    if let Ok(entries) = ramfs::list_dir_entries("/ram") {
        for e in entries.iter().take(MAX_ICONS) {
            if e.name.starts_with('.') { continue; }
            unsafe {
                let len = e.name.len().min(NAME_LEN - 1);
                ICONS[count].name[..len].copy_from_slice(e.name.as_bytes());
                ICONS[count].name_len = len as u8;
                ICONS[count].is_dir = e.is_dir;
            }
            count += 1;
        }
    }
    ICON_COUNT.store(count as u8, Ordering::SeqCst);
}

pub(super) fn draw(w: u32, h: u32) {
    let cnt = ICON_COUNT.load(Ordering::SeqCst) as usize;
    let sel = SELECTED_ICON.load(Ordering::SeqCst) as usize;
    let cols = ((w - ICON_START_X - 20) / ICON_SPACING).max(1) as usize;
    for i in 0..cnt {
        let col = i % cols;
        let row = i / cols;
        let x = ICON_START_X + (col as u32) * ICON_SPACING;
        let y = MENU_BAR_HEIGHT + ICON_START_Y + (row as u32) * ICON_SPACING;
        if y + ICON_SIZE > h - DOCK_HEIGHT { break; }
        let selected = i == sel;
        unsafe { draw_icon(x, y, &ICONS[i], selected); }
    }
}

fn draw_icon(x: u32, y: u32, icon: &DesktopIcon, selected: bool) {
    if selected {
        fill_rect(x, y - 4, ICON_SIZE, ICON_SIZE + 24, 0x403B82F6);
    }
    let bg = if icon.is_dir { 0xFFFFB800 } else { 0xFFFFFFFF };
    let dark = if icon.is_dir { 0xFFCC9200 } else { 0xFFD0D4DA };
    fill_rect(x + 8, y, ICON_SIZE - 16, ICON_SIZE - 8, bg);
    fill_rect(x + 8, y + ICON_SIZE - 12, ICON_SIZE - 16, 4, dark);
    if icon.is_dir { fill_rect(x + 8, y, 16, 8, bg); fill_rect(x + 23, y + 3, 4, 4, bg); }
    else { for i in 0..5 { fill_rect(x + 12, y + 10 + i * 6, 20, 3, 0xFF4D5560); } }
    let name = &icon.name[..icon.name_len as usize];
    let tx = x + ICON_SIZE / 2 - (name.len() as u32 * 4);
    let text_color = if selected { 0xFF60A5FA } else { 0xFFFFFFFF };
    draw_string(tx, y + ICON_SIZE, name, text_color);
}

pub(super) fn handle_click(mx: i32, my: i32, w: u32) -> Option<(&'static str, bool, bool)> {
    let cnt = ICON_COUNT.load(Ordering::SeqCst) as usize;
    let cols = ((w - ICON_START_X - 20) / ICON_SPACING).max(1) as usize;
    let currently_selected = SELECTED_ICON.load(Ordering::SeqCst) as usize;

    for i in 0..cnt {
        let col = i % cols;
        let row = i / cols;
        let x = ICON_START_X + (col as u32) * ICON_SPACING;
        let y = MENU_BAR_HEIGHT + ICON_START_Y + (row as u32) * ICON_SPACING;
        if mx >= x as i32 && mx < (x + ICON_SIZE) as i32 && my >= y as i32 && my < (y + ICON_SIZE + 16) as i32 {
            let should_open = currently_selected == i;
            SELECTED_ICON.store(i as u8, Ordering::SeqCst);
            unsafe {
                static mut PATH_BUF: [u8; 64] = [0; 64];
                PATH_BUF[..5].copy_from_slice(b"/ram/");
                let len = ICONS[i].name_len as usize;
                PATH_BUF[5..5 + len].copy_from_slice(&ICONS[i].name[..len]);
                let is_dir = ICONS[i].is_dir;
                if let Ok(path) = core::str::from_utf8(&PATH_BUF[..5 + len]) {
                    return Some((path, is_dir, should_open));
                }
            }
        }
    }
    SELECTED_ICON.store(255, Ordering::SeqCst);
    None
}

static SELECTED_ICON: AtomicU8 = AtomicU8::new(255);

pub(super) fn create_folder(name: &str) -> bool {
    if name.is_empty() || name.len() >= NAME_LEN { return false; }
    let mut path = [0u8; 80];
    path[..5].copy_from_slice(b"/ram/");
    let len = name.len().min(NAME_LEN - 1);
    path[5..5 + len].copy_from_slice(name.as_bytes());
    if let Ok(path_str) = core::str::from_utf8(&path[..5 + len]) {
        if ramfs::create_dir(path_str).is_ok() {
            refresh();
            return true;
        }
    }
    false
}

pub(super) fn create_file(name: &str) -> bool {
    if name.is_empty() || name.len() >= NAME_LEN { return false; }
    let mut path = [0u8; 80];
    path[..5].copy_from_slice(b"/ram/");
    let len = name.len().min(NAME_LEN - 1);
    path[5..5 + len].copy_from_slice(name.as_bytes());
    if let Ok(path_str) = core::str::from_utf8(&path[..5 + len]) {
        if ramfs::create_file(path_str, b"").is_ok() {
            refresh();
            return true;
        }
    }
    false
}

pub(super) fn delete_selected() -> bool {
    let sel = SELECTED_ICON.load(Ordering::SeqCst);
    if sel == 255 || sel as usize >= ICON_COUNT.load(Ordering::SeqCst) as usize { return false; }
    let icon = unsafe { &ICONS[sel as usize] };
    let mut path = [0u8; 80];
    path[..5].copy_from_slice(b"/ram/");
    let len = icon.name_len as usize;
    path[5..5 + len].copy_from_slice(&icon.name[..len]);
    if let Ok(path_str) = core::str::from_utf8(&path[..5 + len]) {
        if ramfs::delete(path_str).is_ok() {
            SELECTED_ICON.store(255, Ordering::SeqCst);
            refresh();
            return true;
        }
    }
    false
}

pub(super) fn has_selection() -> bool {
    let sel = SELECTED_ICON.load(Ordering::SeqCst);
    sel != 255 && (sel as usize) < ICON_COUNT.load(Ordering::SeqCst) as usize
}

pub(super) fn clear_selection() {
    SELECTED_ICON.store(255, Ordering::SeqCst);
}
