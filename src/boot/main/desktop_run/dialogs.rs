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

use crate::entry::desktop_loop;
use crate::graphics::{desktop, window};

pub fn handle_dialogs() {
    if !window::is_dialog_active() {
        return;
    }
    let result = window::get_dialog_result();
    if result == window::dialog_result::RESULT_NONE {
        return;
    }
    if result == window::dialog_result::RESULT_OK {
        let text = window::get_dialog_input_text();
        if !text.is_empty() {
            process_dialog_input(text);
        }
    }
    window::close_dialog();
    desktop_loop::set_needs_redraw();
}

fn process_dialog_input(text: &str) {
    let cb = window::get_dialog_input_callback();
    match cb {
        x if x == window::dialog_callback::INPUT_CB_DESKTOP_NEW_FOLDER => {
            let _ = desktop::create_desktop_folder(text);
        }
        x if x == window::dialog_callback::INPUT_CB_DESKTOP_NEW_FILE => {
            let _ = desktop::create_desktop_file(text);
        }
        x if x == window::dialog_callback::INPUT_CB_FM_NEW_FOLDER => {
            let _ = window::fm_create_folder(text);
        }
        x if x == window::dialog_callback::INPUT_CB_FM_RENAME => {
            let _ = window::fm_rename_selected(text);
        }
        _ => {}
    }
}
