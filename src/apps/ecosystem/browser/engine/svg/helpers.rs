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

use crate::apps::ecosystem::browser::engine::parser::get_attribute;
use crate::apps::ecosystem::browser::engine::types::Node;
use alloc::vec::Vec;

pub(super) fn attr_u32(node: &Node, name: &str) -> Option<u32> {
    get_attribute(node, name).and_then(|v| parse_dimension(&v))
}

pub(super) fn attr_i32(node: &Node, name: &str) -> Option<i32> {
    get_attribute(node, name).and_then(|v| parse_i32(&v))
}

pub(super) fn parse_dimension(s: &str) -> Option<u32> {
    s.trim().trim_end_matches("px").parse::<u32>().ok()
}

pub(super) fn parse_i32(s: &str) -> Option<i32> {
    s.trim().trim_end_matches("px").parse::<i32>().ok()
}

pub(super) fn parse_points(s: &str) -> Vec<(i32, i32)> {
    let mut result = Vec::new();
    for pair in s.split_whitespace() {
        let parts: Vec<&str> = pair.split(',').collect();
        if parts.len() == 2 {
            if let (Some(x), Some(y)) = (parse_i32(parts[0]), parse_i32(parts[1])) {
                result.push((x, y));
            }
        }
    }
    result
}
