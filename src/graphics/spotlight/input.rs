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

use super::results::{search, search_count, ResultAction};
use super::state::{
    close, get_query, get_selected, is_open, pop_char, push_char, select_next, select_prev,
};
use crate::graphics::window;

pub fn handle_key(key: u8, ctrl: bool) -> bool {
    if !is_open() {
        return false;
    }
    match key {
        0x1B => {
            close();
            return true;
        }
        0x0D => {
            execute_selected();
            close();
            return true;
        }
        0x08 | 0x7F => {
            pop_char();
            return true;
        }
        0x26 => {
            select_prev();
            return true;
        }
        0x28 => {
            select_next(result_count());
            return true;
        }
        c if c >= 0x20 && c < 0x7F && !ctrl => {
            push_char(c);
            return true;
        }
        _ => {}
    }
    false
}

pub fn handle_click(mx: i32, my: i32, sw: u32) -> bool {
    if !is_open() {
        return false;
    }
    let width = 600u32;
    let x = (sw - width) / 2;
    let y = 120u32;
    let input_h = 56u32;
    let result_h = 44u32;
    if mx < x as i32 || mx >= (x + width) as i32 {
        close();
        return true;
    }
    if my < y as i32 {
        close();
        return true;
    }
    let rel_y = my - y as i32;
    if rel_y >= input_h as i32 {
        let result_idx = ((rel_y - input_h as i32) / result_h as i32) as usize;
        if result_idx < result_count() {
            select_result(result_idx);
            execute_selected();
            close();
            return true;
        }
    }
    true
}

fn result_count() -> usize {
    let (query, len) = get_query();
    search_count(&query[..len]).min(8)
}

fn select_result(idx: usize) {
    for _ in 0..idx {
        select_next(result_count());
    }
}

fn execute_selected() {
    let (query, len) = get_query();
    let selected = get_selected();
    let action = search(&query[..len]).nth(selected).map(|r| r.action);
    if let Some(act) = action {
        match act {
            ResultAction::OpenApp(wtype) => {
                window::open(wtype);
            }
            ResultAction::OpenSetting(page) => {
                window::open(window::WindowType::Settings);
                crate::graphics::window::settings::state::set_page(page);
            }
            ResultAction::OpenFile => {}
            ResultAction::RunCommand => {}
        }
    }
}
