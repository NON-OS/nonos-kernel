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

use core::sync::atomic::Ordering;
use super::state::*;
use super::{buffer, cursor, file, find};
use super::input_click;

pub(super) fn handle_key(ch: u8) {
    if find::is_active() {
        if find::is_replace_mode() {
            find::handle_replace_key(ch);
        } else {
            find::handle_find_key(ch);
        }
        return;
    }

    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);

    match ch {
        8 | 127 => {
            if EDITOR_HAS_SELECTION.load(Ordering::Relaxed) {
                buffer::delete_selection();
            } else {
                buffer::delete_backward();
            }
        }
        13 => {
            if EDITOR_HAS_SELECTION.load(Ordering::Relaxed) {
                buffer::delete_selection();
            }
            buffer::insert_newline();
        }
        9 => {
            if EDITOR_HAS_SELECTION.load(Ordering::Relaxed) {
                buffer::delete_selection();
            }
            buffer::insert_tab();
        }
        32..=126 => {
            if EDITOR_HAS_SELECTION.load(Ordering::Relaxed) {
                buffer::delete_selection();
            }
            buffer::insert_char(ch);
        }
        _ => {}
    }
}

pub(super) fn handle_special_key(key: SpecialKey) {
    if find::is_active() {
        match key {
            SpecialKey::Escape => find::close_find(),
            SpecialKey::F3 | SpecialKey::CtrlG => { let _ = find::find_next(); }
            SpecialKey::ShiftF3 => { let _ = find::find_prev(); }
            _ => {}
        }
        return;
    }

    match key {
        SpecialKey::Left => cursor::move_left(),
        SpecialKey::Right => cursor::move_right(),
        SpecialKey::Up => cursor::move_up(),
        SpecialKey::Down => cursor::move_down(),
        SpecialKey::Home => cursor::move_to_line_start(),
        SpecialKey::End => cursor::move_to_line_end(),
        SpecialKey::PageUp => {
            for _ in 0..20 {
                cursor::move_up();
            }
        }
        SpecialKey::PageDown => {
            for _ in 0..20 {
                cursor::move_down();
            }
        }
        SpecialKey::Delete => {
            if EDITOR_HAS_SELECTION.load(Ordering::Relaxed) {
                buffer::delete_selection();
            } else {
                buffer::delete_forward();
            }
        }
        SpecialKey::CtrlA => buffer::select_all(),
        SpecialKey::CtrlS => { file::save_file(); }
        SpecialKey::CtrlN => file::new_file(),
        SpecialKey::CtrlW => file::close_file(),
        SpecialKey::CtrlHome => cursor::move_to_start(),
        SpecialKey::CtrlEnd => cursor::move_to_end(),
        SpecialKey::CtrlLeft => cursor::move_word_left(),
        SpecialKey::CtrlRight => cursor::move_word_right(),
        SpecialKey::CtrlF => find::open_find(),
        SpecialKey::CtrlH => find::open_replace(),
        SpecialKey::F3 => { let _ = find::find_next(); }
        SpecialKey::ShiftF3 => { let _ = find::find_prev(); }
        SpecialKey::CtrlG => { let _ = find::find_next(); }
        SpecialKey::Escape => find::close_find(),
        SpecialKey::CtrlC => { buffer::copy_selection(); }
        SpecialKey::CtrlX => { buffer::cut_selection(); }
        SpecialKey::CtrlV => { buffer::paste(); }
        SpecialKey::CtrlZ => { buffer::undo(); }
        SpecialKey::CtrlY => { buffer::redo(); }
    }
}

#[derive(Clone, Copy)]
pub enum SpecialKey {
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Delete,
    Escape,
    CtrlA,
    CtrlS,
    CtrlN,
    CtrlW,
    CtrlF,
    CtrlH,
    CtrlG,
    CtrlC,
    CtrlV,
    CtrlX,
    CtrlZ,
    CtrlY,
    CtrlHome,
    CtrlEnd,
    CtrlLeft,
    CtrlRight,
    F3,
    ShiftF3,
}

pub(super) fn handle_click(win_x: u32, win_y: u32, win_w: u32, win_h: u32, click_x: i32, click_y: i32) -> bool {
    input_click::handle_click(win_x, win_y, win_w, win_h, click_x, click_y)
}
