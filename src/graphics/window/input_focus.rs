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
use super::state::{WINDOWS, FOCUSED_WINDOW, MAX_WINDOWS, WindowType};

pub fn is_editor_focused() -> bool {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return false;
    }
    WINDOWS[focused].window_type.load(Ordering::Relaxed) == WindowType::TextEditor as u32
}

pub fn is_terminal_focused() -> bool {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return false;
    }
    WINDOWS[focused].window_type.load(Ordering::Relaxed) == WindowType::Terminal as u32
}

pub fn is_browser_focused() -> bool {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return false;
    }
    WINDOWS[focused].window_type.load(Ordering::Relaxed) == WindowType::Browser as u32
}

pub fn is_wallet_focused() -> bool {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return false;
    }
    WINDOWS[focused].window_type.load(Ordering::Relaxed) == WindowType::Wallet as u32
}

pub fn is_ecosystem_focused() -> bool {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return false;
    }
    WINDOWS[focused].window_type.load(Ordering::Relaxed) == WindowType::Ecosystem as u32
}

pub fn is_file_manager_focused() -> bool {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return false;
    }
    WINDOWS[focused].window_type.load(Ordering::Relaxed) == WindowType::FileManager as u32
}

pub fn is_text_input_focused() -> bool {
    is_editor_focused() || is_terminal_focused() || is_browser_focused() || is_wallet_focused() || is_ecosystem_focused()
}
