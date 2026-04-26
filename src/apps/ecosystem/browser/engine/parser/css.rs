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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn parse_style_classes(css: &str, hidden: &mut Vec<String>, centered: &mut Vec<String>) {
    let css_lower = css.to_ascii_lowercase();
    let bytes = css_lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            i += 1;
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b'_') { i += 1; }
            if i > start {
                let class_name = &css_lower[start..i];
                while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
                if i < bytes.len() && bytes[i] == b'{' {
                    i += 1;
                    let block_start = i;
                    while i < bytes.len() && bytes[i] != b'}' { i += 1; }
                    let block = &css_lower[block_start..i];
                    if (block.contains("display") && block.contains("none")) || (block.contains("visibility") && block.contains("hidden")) {
                        hidden.push(String::from(class_name));
                    }
                    if class_centers_content(block) {
                        centered.push(String::from(class_name));
                    }
                    if i < bytes.len() { i += 1; }
                }
            }
        } else { i += 1; }
    }
}

fn class_centers_content(block: &str) -> bool {
    block.contains("text-align") && block.contains("center")
        || block.contains("justify-content") && block.contains("center")
        || block.contains("place-items") && block.contains("center")
        || block.contains("margin") && block.contains("auto")
}
