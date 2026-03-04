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
use super::manager;
use super::file_manager;
use super::notifications::{self, NOTIFY_INFO};

const CTRL_C: u8 = 3;
const CTRL_V: u8 = 22;
const CTRL_X: u8 = 24;
const CTRL_W: u8 = 23;
const CTRL_Q: u8 = 17;
const CTRL_N: u8 = 14;
const CTRL_Z: u8 = 26;

pub fn handle_shortcut(ch: u8) -> bool {
    match ch {
        CTRL_W | CTRL_Q => {
            let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
            if focused < MAX_WINDOWS && WINDOWS[focused].active.load(Ordering::Relaxed) {
                manager::close(focused);
                return true;
            }
            false
        }
        CTRL_C => {
            if handle_file_manager_shortcut(ShortcutAction::Copy) {
                return true;
            }
            false
        }
        CTRL_X => {
            if handle_file_manager_shortcut(ShortcutAction::Cut) {
                return true;
            }
            false
        }
        CTRL_V => {
            if handle_file_manager_shortcut(ShortcutAction::Paste) {
                return true;
            }
            false
        }
        CTRL_N => {
            if handle_file_manager_shortcut(ShortcutAction::NewFolder) {
                return true;
            }
            false
        }
        CTRL_Z => {
            false
        }
        _ => false,
    }
}

enum ShortcutAction {
    Copy,
    Cut,
    Paste,
    NewFolder,
}

fn handle_file_manager_shortcut(action: ShortcutAction) -> bool {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return false;
    }

    let wtype = window_type_from_u32(WINDOWS[focused].window_type.load(Ordering::Relaxed));
    if wtype != WindowType::FileManager {
        return false;
    }

    match action {
        ShortcutAction::Copy => {
            match file_manager::copy_selected() {
                file_manager::FmResult::Ok => {
                    notifications::push(NOTIFY_INFO,b"Copied to clipboard");
                    true
                }
                file_manager::FmResult::NotFound => {
                    notifications::push(NOTIFY_INFO,b"No file selected");
                    true
                }
                _ => true,
            }
        }
        ShortcutAction::Cut => {
            match file_manager::cut_selected() {
                file_manager::FmResult::Ok => {
                    notifications::push(NOTIFY_INFO,b"Cut to clipboard");
                    true
                }
                file_manager::FmResult::NotFound => {
                    notifications::push(NOTIFY_INFO,b"No file selected");
                    true
                }
                _ => true,
            }
        }
        ShortcutAction::Paste => {
            match file_manager::paste() {
                file_manager::FmResult::Ok => {
                    notifications::push(NOTIFY_INFO,b"Pasted");
                    true
                }
                file_manager::FmResult::NotFound => {
                    notifications::push(NOTIFY_INFO,b"Clipboard empty");
                    true
                }
                file_manager::FmResult::AlreadyExists => {
                    notifications::push(NOTIFY_INFO,b"File already exists");
                    true
                }
                _ => {
                    notifications::push(NOTIFY_INFO,b"Paste failed");
                    true
                }
            }
        }
        ShortcutAction::NewFolder => {
            match file_manager::create_folder("NEWFOLDER") {
                file_manager::FmResult::Ok => {
                    notifications::push(NOTIFY_INFO,b"Folder created");
                    true
                }
                _ => {
                    notifications::push(NOTIFY_INFO,b"Create failed");
                    true
                }
            }
        }
    }
}
