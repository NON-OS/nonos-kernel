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

use super::state::set_needs_redraw;
use crate::graphics::desktop;
use crate::graphics::window::context_menu::actions::*;
use crate::graphics::window::{self, WindowType};
use crate::sys::serial;
use core::sync::atomic::Ordering;

pub fn handle_context_menu_action(action: u8) {
    match action {
        DESKTOP_REFRESH => {
            desktop::refresh_desktop_icons();
            set_needs_redraw();
        }
        DESKTOP_SETTINGS => {
            window::open(WindowType::Settings);
        }
        DESKTOP_ABOUT => {
            window::open(WindowType::About);
        }
        DESKTOP_NEW_FOLDER => {
            serial::println(b"[DLG] showing new folder dialog");
            window::show_input_dialog(
                b"New Folder",
                b"Enter folder name:",
                window::dialog_callback::INPUT_CB_DESKTOP_NEW_FOLDER,
            );
            set_needs_redraw();
        }
        DESKTOP_NEW_FILE => {
            serial::println(b"[DLG] showing new file dialog");
            window::show_input_dialog(
                b"New File",
                b"Enter file name:",
                window::dialog_callback::INPUT_CB_DESKTOP_NEW_FILE,
            );
            set_needs_redraw();
        }
        DESKTOP_DELETE => {
            desktop::delete_desktop_selected();
            set_needs_redraw();
        }
        DESKTOP_GO_BACK => {
            desktop::desktop_navigate_back();
            set_needs_redraw();
        }
        FM_OPEN => {
            window::fm_open_selected();
        }
        FM_COPY => {
            let _ = window::fm_copy_selected();
        }
        FM_CUT => {
            let _ = window::fm_cut_selected();
        }
        FM_PASTE => {
            let _ = window::fm_paste();
        }
        FM_DELETE => {
            let _ = window::fm_delete_selected();
        }
        FM_RENAME => {
            window::show_input_dialog(
                b"Rename",
                b"Enter new name:",
                window::dialog_callback::INPUT_CB_FM_RENAME,
            );
            set_needs_redraw();
        }
        FM_NEW_FOLDER => {
            window::show_input_dialog(
                b"New Folder",
                b"Enter folder name:",
                window::dialog_callback::INPUT_CB_FM_NEW_FOLDER,
            );
            set_needs_redraw();
        }
        EDIT_CUT => {
            window::text_editor::editor_cut();
        }
        EDIT_COPY => {
            window::text_editor::editor_copy();
        }
        EDIT_PASTE => {
            window::text_editor::editor_paste();
        }
        EDIT_SELECT_ALL => {
            window::text_editor::editor_select_all();
        }
        WIN_MINIMIZE => {
            let focused = window::FOCUSED_WINDOW.load(Ordering::Relaxed);
            if focused < window::MAX_WINDOWS {
                window::minimize(focused);
            }
        }
        WIN_MAXIMIZE => {
            let focused = window::FOCUSED_WINDOW.load(Ordering::Relaxed);
            if focused < window::MAX_WINDOWS {
                window::maximize(focused);
            }
        }
        WIN_CLOSE => {
            let focused = window::FOCUSED_WINDOW.load(Ordering::Relaxed);
            if focused < window::MAX_WINDOWS {
                window::close(focused);
            }
        }
        _ => {}
    }
    set_needs_redraw();
}
