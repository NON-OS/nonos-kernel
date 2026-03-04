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
use super::state::{WINDOWS, FOCUSED_WINDOW, MAX_WINDOWS, WindowType, window_type_from_u32};
use super::text_editor::editor_key_impl;
use super::apps::{browser_key, wallet_key, ecosystem_key};

pub(super) fn handle_key(ch: u8) {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return;
    }

    let wtype = window_type_from_u32(WINDOWS[focused].window_type.load(Ordering::Relaxed));
    match wtype {
        WindowType::TextEditor => {
            editor_key_impl(ch);
        }
        WindowType::Terminal => {
            super::terminal::terminal_key(ch);
        }
        WindowType::Browser => {
            browser_key(ch);
        }
        WindowType::Wallet => {
            wallet_key(ch);
        }
        WindowType::Ecosystem => {
            ecosystem_key(ch);
        }
        _ => {}
    }
}

pub(super) fn browser_special_key(key: crate::graphics::window::text_editor::SpecialKey) {
    super::apps::browser_special_key(key);
}

pub(super) fn wallet_special_key(key: crate::graphics::window::text_editor::SpecialKey) {
    super::apps::wallet_special_key(key);
}

pub(super) fn ecosystem_special_key(key: crate::graphics::window::text_editor::SpecialKey) {
    super::apps::ecosystem_special_key(key);
}
