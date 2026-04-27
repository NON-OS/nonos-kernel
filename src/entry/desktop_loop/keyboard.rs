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
use crate::graphics::window;
use crate::input::{keyboard, KeyEvent};

pub fn handle_keyboard_input() {
    handle_dialog_input();
    handle_alt_shortcuts();
    handle_editor_keys();
    handle_browser_keys();
    handle_file_manager_keys();
}

fn handle_dialog_input() {
    if let Some(ch) = crate::input::poll_keyboard_unified() {
        if window::is_input_dialog_active() {
            crate::sys::serial::print(b"[DLG] key=");
            crate::sys::serial::print_dec(ch as u64);
            crate::sys::serial::println(b"");
            window::handle_dialog_key(ch);
            set_needs_redraw();
        } else if window::handle_shortcut(ch) {
            set_needs_redraw();
        } else if window::is_text_input_focused() {
            window::handle_key(ch);
            set_needs_redraw();
        }
    }
}

fn handle_alt_shortcuts() {
    if keyboard::is_alt_pressed() {
        if let Some(ch) = crate::input::poll_keyboard_unified() {
            if ch == 0x09 {
                window::cycle_window();
                set_needs_redraw();
                return;
            }
        }
        if let Some(evt) = crate::input::poll_special_key() {
            match evt {
                KeyEvent::Left => {
                    window::snap_left();
                    set_needs_redraw();
                }
                KeyEvent::Right => {
                    window::snap_right();
                    set_needs_redraw();
                }
                KeyEvent::Up => {
                    window::snap_top();
                    set_needs_redraw();
                }
                KeyEvent::Down => {
                    window::unsnap_focused();
                    set_needs_redraw();
                }
                _ => {}
            }
        }
    }
}

fn handle_editor_keys() {
    if window::is_editor_focused() {
        if let Some(evt) = crate::input::poll_special_key() {
            use crate::graphics::window::text_editor::{editor_special_key, SpecialKey};
            let special = match evt {
                KeyEvent::Up => Some(SpecialKey::Up),
                KeyEvent::Down => Some(SpecialKey::Down),
                KeyEvent::Left => Some(SpecialKey::Left),
                KeyEvent::Right => Some(SpecialKey::Right),
                KeyEvent::Home => Some(SpecialKey::Home),
                KeyEvent::End => Some(SpecialKey::End),
                KeyEvent::PageUp => Some(SpecialKey::PageUp),
                KeyEvent::PageDown => Some(SpecialKey::PageDown),
                KeyEvent::Delete => Some(SpecialKey::Delete),
                _ => None,
            };
            if let Some(key) = special {
                editor_special_key(key);
                set_needs_redraw();
            }
        }
    }
}

fn handle_browser_keys() {
    if window::is_browser_focused() {
        if let Some(evt) = crate::input::poll_special_key() {
            use crate::graphics::window::text_editor::SpecialKey;
            let special = match evt {
                KeyEvent::Up => Some(SpecialKey::Up),
                KeyEvent::Down => Some(SpecialKey::Down),
                KeyEvent::Left => Some(SpecialKey::Left),
                KeyEvent::Right => Some(SpecialKey::Right),
                KeyEvent::Home => Some(SpecialKey::Home),
                KeyEvent::End => Some(SpecialKey::End),
                KeyEvent::PageUp => Some(SpecialKey::PageUp),
                KeyEvent::PageDown => Some(SpecialKey::PageDown),
                KeyEvent::Delete => Some(SpecialKey::Delete),
                _ => None,
            };
            if let Some(key) = special {
                window::browser_special_key(key);
                set_needs_redraw();
            }
        }
    }
}

fn handle_file_manager_keys() {
    if window::is_file_manager_focused() {
        if let Some(evt) = crate::input::poll_special_key() {
            let scancode = match evt {
                KeyEvent::Backspace => Some(0x0E),
                KeyEvent::Enter => Some(0x1C),
                KeyEvent::Escape => Some(0x01),
                _ => None,
            };
            if let Some(sc) = scancode {
                if window::file_manager_special_key(sc) {
                    set_needs_redraw();
                }
            }
        }
    }
}
