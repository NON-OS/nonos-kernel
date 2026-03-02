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

use crate::shell::terminal::history;

use super::types::get_editor;

pub fn handle_key(scancode: u8, ch: u8, ctrl: bool, alt: bool) -> Option<&'static [u8]> {
    let editor = get_editor();

    if ctrl {
        match ch {
            b'a' | b'A' => editor.move_home(),
            b'e' | b'E' => editor.move_end(),
            b'b' | b'B' => editor.move_left(),
            b'f' | b'F' => editor.move_right(),
            b'h' | b'H' => editor.backspace(),
            b'd' | b'D' => editor.delete_char(),
            b'k' | b'K' => editor.delete_to_end(),
            b'u' | b'U' => editor.delete_to_start(),
            b'w' | b'W' => editor.delete_word_left(),
            b'l' | b'L' => {
                crate::shell::terminal::scroll();
                editor.redraw();
            }
            b'c' | b'C' => {
                editor.clear_line();
            }
            _ => {}
        }
        return None;
    }

    if alt {
        match ch {
            b'b' | b'B' => editor.move_word_left(),
            b'f' | b'F' => editor.move_word_right(),
            b'd' | b'D' => {
                let pos = editor.cursor_pos();
                editor.move_word_right();
                let end = editor.cursor_pos();
                for _ in pos..end {
                    editor.delete_char();
                }
            }
            _ => {}
        }
        return None;
    }

    match scancode {
        0x48 => {
            editor.history_prev();
        }
        0x50 => {
            editor.history_next();
        }
        0x4B => {
            editor.move_left();
        }
        0x4D => {
            editor.move_right();
        }
        0x47 => {
            editor.move_home();
        }
        0x4F => {
            editor.move_end();
        }
        0x53 => {
            editor.delete_char();
        }
        0x0E => {
            editor.backspace();
        }
        0x1C => {
            let content = editor.get_content();
            if !content.is_empty() {
                history::add_command(content);
            }
            return Some(content);
        }
        _ => {
            if ch >= 0x20 && ch < 0x7F {
                editor.insert_char(ch);
            }
        }
    }

    None
}
