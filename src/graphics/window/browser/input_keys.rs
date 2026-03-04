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

use crate::graphics::window::text_editor::SpecialKey;

use super::constants::*;
use super::state::*;
use super::http::navigate;
use super::find;

pub(super) fn handle_key(ch: u8) {
    if find::is_active() {
        find::handle_key(ch);
        return;
    }

    if !URL_FOCUSED.load(Ordering::Relaxed) {
        match ch {
            0x1B => {}
            _ => URL_FOCUSED.store(true, Ordering::Relaxed),
        }
        return;
    }

    match ch {
        0x08 | 0x7F => {
            let cursor = URL_CURSOR.load(Ordering::Relaxed);
            if cursor > 0 {
                let mut url_buf = URL_BUFFER.lock();
                let len = URL_LEN.load(Ordering::Relaxed);
                for i in cursor - 1..len - 1 {
                    url_buf[i] = url_buf[i + 1];
                }
                url_buf[len - 1] = 0;
                URL_LEN.store(len - 1, Ordering::Relaxed);
                URL_CURSOR.store(cursor - 1, Ordering::Relaxed);
            }
        }

        0x0D | 0x0A => navigate(),

        0x1B => {
            let len = URL_LEN.load(Ordering::Relaxed);
            if len > 0 {
                let mut url_buf = URL_BUFFER.lock();
                *url_buf = [0u8; MAX_URL_LEN];
                URL_LEN.store(0, Ordering::Relaxed);
                URL_CURSOR.store(0, Ordering::Relaxed);
            } else {
                URL_FOCUSED.store(false, Ordering::Relaxed);
            }
        }

        _ if ch >= 0x20 && ch < 0x7F => {
            let mut url_buf = URL_BUFFER.lock();
            let len = URL_LEN.load(Ordering::Relaxed);
            let cursor = URL_CURSOR.load(Ordering::Relaxed);

            if len < MAX_URL_LEN - 1 {
                for i in (cursor..len).rev() {
                    url_buf[i + 1] = url_buf[i];
                }
                url_buf[cursor] = ch;
                URL_LEN.store(len + 1, Ordering::Relaxed);
                URL_CURSOR.store(cursor + 1, Ordering::Relaxed);
            }
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
        SpecialKey::Left => {
            let cursor = URL_CURSOR.load(Ordering::Relaxed);
            if cursor > 0 {
                URL_CURSOR.store(cursor - 1, Ordering::Relaxed);
            }
        }

        SpecialKey::Right => {
            let cursor = URL_CURSOR.load(Ordering::Relaxed);
            let len = URL_LEN.load(Ordering::Relaxed);
            if cursor < len {
                URL_CURSOR.store(cursor + 1, Ordering::Relaxed);
            }
        }

        SpecialKey::Home => {
            if URL_FOCUSED.load(Ordering::Relaxed) {
                URL_CURSOR.store(0, Ordering::Relaxed);
            } else {
                SCROLL_OFFSET.store(0, Ordering::Relaxed);
            }
        }

        SpecialKey::End => {
            if URL_FOCUSED.load(Ordering::Relaxed) {
                let len = URL_LEN.load(Ordering::Relaxed);
                URL_CURSOR.store(len, Ordering::Relaxed);
            } else {
                let lines = PAGE_LINES.lock();
                if lines.len() > 20 {
                    SCROLL_OFFSET.store(lines.len() - 20, Ordering::Relaxed);
                }
            }
        }

        SpecialKey::Up => {
            let scroll = SCROLL_OFFSET.load(Ordering::Relaxed);
            if scroll > 0 {
                SCROLL_OFFSET.store(scroll - 1, Ordering::Relaxed);
            }
        }

        SpecialKey::Down => {
            let lines = PAGE_LINES.lock();
            let scroll = SCROLL_OFFSET.load(Ordering::Relaxed);
            if scroll + 1 < lines.len() {
                SCROLL_OFFSET.store(scroll + 1, Ordering::Relaxed);
            }
        }

        SpecialKey::PageUp => {
            let scroll = SCROLL_OFFSET.load(Ordering::Relaxed);
            SCROLL_OFFSET.store(scroll.saturating_sub(20), Ordering::Relaxed);
        }

        SpecialKey::PageDown => {
            let lines = PAGE_LINES.lock();
            let scroll = SCROLL_OFFSET.load(Ordering::Relaxed);
            let new_scroll = (scroll + 20).min(lines.len().saturating_sub(1));
            SCROLL_OFFSET.store(new_scroll, Ordering::Relaxed);
        }

        SpecialKey::Delete => {
            let cursor = URL_CURSOR.load(Ordering::Relaxed);
            let len = URL_LEN.load(Ordering::Relaxed);
            if cursor < len {
                let mut url_buf = URL_BUFFER.lock();
                for i in cursor..len - 1 {
                    url_buf[i] = url_buf[i + 1];
                }
                url_buf[len - 1] = 0;
                URL_LEN.store(len - 1, Ordering::Relaxed);
            }
        }

        SpecialKey::CtrlF => {
            find::open_find();
        }

        SpecialKey::F3 | SpecialKey::CtrlG => {
            if find::get_match_count() > 0 {
                find::find_next();
            } else {
                find::open_find();
            }
        }

        SpecialKey::ShiftF3 => {
            if find::get_match_count() > 0 {
                find::find_prev();
            }
        }

        SpecialKey::Escape => {
            if find::is_active() {
                find::close_find();
            } else {
                URL_FOCUSED.store(false, Ordering::Relaxed);
            }
        }

        _ => {}
    }
}

pub(super) fn is_url_focused() -> bool {
    URL_FOCUSED.load(Ordering::Relaxed)
}
