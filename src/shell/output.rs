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

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static GUI_OUTPUT_ACTIVE: AtomicBool = AtomicBool::new(false);
static GUI_WINDOW_ID: AtomicUsize = AtomicUsize::new(0);

pub fn enable_gui_output(window_id: usize) {
    GUI_WINDOW_ID.store(window_id, Ordering::SeqCst);
    GUI_OUTPUT_ACTIVE.store(true, Ordering::SeqCst);
}

pub fn disable_gui_output() {
    GUI_OUTPUT_ACTIVE.store(false, Ordering::SeqCst);
}

pub fn is_gui_output() -> bool {
    GUI_OUTPUT_ACTIVE.load(Ordering::SeqCst)
}

pub fn get_gui_window_id() -> usize {
    GUI_WINDOW_ID.load(Ordering::SeqCst)
}

pub fn print_line(text: &[u8], color: u32) {
    if crate::shell::commands::pipeline::is_capturing() {
        crate::shell::commands::pipeline::capture_output(text);
        return;
    }

    if is_gui_output() {
        crate::graphics::window::terminal::buffer::print_line(text, color);
    } else {
        crate::shell::terminal::print_line(text, color);
    }
}

pub fn put_char(ch: u8, color: u32) {
    if is_gui_output() {
        crate::graphics::window::terminal::buffer::put_char(ch, color);
    } else {
        let buf = [ch];
        crate::shell::terminal::print_line(&buf, color);
    }
}

pub fn newline() {
    if is_gui_output() {
        crate::graphics::window::terminal::buffer::newline();
    } else {
        crate::shell::terminal::print_line(b"", 0xFFFFFFFF);
    }
}
