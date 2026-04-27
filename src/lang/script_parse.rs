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

pub fn find_block_end(lines: &[&str], start: usize) -> (usize, usize) {
    let base_indent = get_indent(lines[start]);
    let mut i = start + 1;
    let mut else_line = 0usize;
    while i < lines.len() {
        let line = lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        let indent = get_indent(line);
        if indent <= base_indent {
            if line.trim().starts_with("else") {
                else_line = i;
                i += 1;
                continue;
            }
            return (i, else_line);
        }
        i += 1;
    }
    (i, else_line)
}

fn get_indent(line: &str) -> usize {
    let mut count = 0;
    for c in line.chars() {
        match c {
            ' ' => count += 1,
            '\t' => count += 4,
            _ => break,
        }
    }
    count
}

pub fn count_leading_spaces(line: &str) -> usize {
    get_indent(line)
}
