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

use core::sync::atomic::Ordering;

use crate::graphics::window::text_editor::SpecialKey;

use super::constants::*;
use super::state::*;
use super::http::{go_back, go_forward, refresh, navigate, fetch_page};
use super::input_keys;

pub(super) fn handle_click(win_x: u32, win_y: u32, win_w: u32, _win_h: u32, click_x: i32, click_y: i32) -> bool {
    let rel_x = click_x - win_x as i32;
    let rel_y = click_y - win_y as i32;

    if rel_y < 28 {
        return false;
    }

    let toolbar_y = 28i32;

    if rel_y >= toolbar_y && rel_y < toolbar_y + TOOLBAR_HEIGHT as i32 {
        if rel_x >= 10 && rel_x < 35 && rel_y >= toolbar_y + 8 && rel_y < toolbar_y + 32 {
            go_back();
            return true;
        }

        if rel_x >= 40 && rel_x < 65 && rel_y >= toolbar_y + 8 && rel_y < toolbar_y + 32 {
            go_forward();
            return true;
        }

        if rel_x >= 70 && rel_x < 95 && rel_y >= toolbar_y + 8 && rel_y < toolbar_y + 32 {
            refresh();
            return true;
        }

        let url_bar_x = 105i32;
        let url_bar_w = (win_w as i32).saturating_sub(175);
        if rel_x >= url_bar_x && rel_x < url_bar_x + url_bar_w && rel_y >= toolbar_y + 8 && rel_y < toolbar_y + 32 {
            URL_FOCUSED.store(true, Ordering::Relaxed);
            let char_pos = ((rel_x - url_bar_x - 8) / 8) as usize;
            let url_len = URL_LEN.load(Ordering::Relaxed);
            URL_CURSOR.store(char_pos.min(url_len), Ordering::Relaxed);
            return true;
        }

        let go_x = (win_w as i32) - 60;
        if rel_x >= go_x && rel_x < go_x + 50 && rel_y >= toolbar_y + 8 && rel_y < toolbar_y + 32 {
            navigate();
            return true;
        }
    }

    if rel_y >= toolbar_y + TOOLBAR_HEIGHT as i32 {
        URL_FOCUSED.store(false, Ordering::Relaxed);

        let content_y = (rel_y - toolbar_y - TOOLBAR_HEIGHT as i32) as usize;
        let line_height = 16usize;
        let scroll = SCROLL_OFFSET.load(Ordering::Relaxed);
        let clicked_line = scroll + content_y / line_height;

        let content_x = (rel_x - CONTENT_PADDING as i32).max(0) as usize;
        let char_offset = content_x / 8;

        if let Some(href) = find_link_at(clicked_line, char_offset) {
            let url = if href.starts_with("http://") || href.starts_with("https://") {
                href
            } else if href.starts_with('/') {
                if let Some(current_url) = get_url_string() {
                    if let Some(slash_pos) = current_url.find("://") {
                        if let Some(path_start) = current_url[slash_pos + 3..].find('/') {
                            alloc::format!("{}{}", &current_url[..slash_pos + 3 + path_start], href)
                        } else {
                            alloc::format!("{}{}", current_url, href)
                        }
                    } else {
                        alloc::format!("http://{}{}", current_url, href)
                    }
                } else {
                    href
                }
            } else {
                if let Some(current_url) = get_url_string() {
                    if let Some(last_slash) = current_url.rfind('/') {
                        alloc::format!("{}/{}", &current_url[..last_slash], href)
                    } else {
                        alloc::format!("{}/{}", current_url, href)
                    }
                } else {
                    href
                }
            };

            set_url(&url);
            fetch_page(&url);
            return true;
        }

        return true;
    }

    false
}

pub(super) fn handle_key(ch: u8) {
    input_keys::handle_key(ch);
}

pub(super) fn handle_special_key(key: SpecialKey) {
    input_keys::handle_special_key(key);
}

pub(super) fn is_url_focused() -> bool {
    input_keys::is_url_focused()
}
