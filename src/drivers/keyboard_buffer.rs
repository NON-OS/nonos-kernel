// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::collections::VecDeque;
use spin::Mutex;

static KEYBOARD_BUFFER: Mutex<VecDeque<char>> = Mutex::new(VecDeque::new());

pub fn add_to_buffer(ch: char) {
    let mut buffer = KEYBOARD_BUFFER.lock();
    buffer.push_back(ch);

    if buffer.len() > 256 {
        buffer.pop_front();
    }
}

pub fn read_char() -> Option<char> {
    let mut buffer = KEYBOARD_BUFFER.lock();
    buffer.pop_front()
}

pub fn has_data() -> bool {
    let buffer = KEYBOARD_BUFFER.lock();
    !buffer.is_empty()
}

pub fn available_count() -> usize {
    let buffer = KEYBOARD_BUFFER.lock();
    buffer.len()
}
