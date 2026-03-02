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

pub fn is_whitespace(c: char) -> bool {
    c == ' ' || c == '\t'
}

pub fn is_word_char(c: char, big_word: bool) -> bool {
    if big_word {
        !is_whitespace(c)
    } else {
        c.is_alphanumeric() || c == '_'
    }
}

pub fn is_word_boundary(chars: &[char], idx: usize, big_word: bool) -> bool {
    if idx == 0 || idx >= chars.len() {
        return true;
    }

    let prev = chars[idx - 1];
    let curr = chars[idx];

    is_word_char(prev, big_word) != is_word_char(curr, big_word)
}
