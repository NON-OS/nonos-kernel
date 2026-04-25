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

use crate::apps::ecosystem::browser::engine::types::{Node, NodeType};
use alloc::string::String;

pub(crate) fn get_attribute(node: &Node, name: &str) -> Option<String> {
    node.attributes.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
}

pub(crate) fn extract_text(node: &Node) -> String {
    let mut text = String::new();
    match &node.node_type {
        NodeType::Text(t) => text.push_str(t),
        NodeType::Element(_) => {
            for child in &node.children {
                text.push_str(&extract_text(child));
            }
        }
        NodeType::Comment(_) => {}
    }
    text
}

pub(crate) fn strip_tags(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut in_script = false;
    let mut tag_buf = String::new();
    for c in html.chars() {
        if c == '<' {
            in_tag = true;
            tag_buf.clear();
            continue;
        }
        if c == '>' {
            in_tag = false;
            let lower = tag_buf.to_ascii_lowercase();
            if lower.starts_with("script") {
                in_script = true;
            }
            if lower.starts_with("/script") {
                in_script = false;
            }
            if lower.starts_with("br")
                || lower.starts_with("p")
                || lower.starts_with("/p")
                || lower.starts_with("/div")
            {
                out.push('\n');
            }
            continue;
        }
        if in_tag {
            tag_buf.push(c);
            continue;
        }
        if in_script {
            continue;
        }
        out.push(c);
    }
    out.split_whitespace().collect::<alloc::vec::Vec<_>>().join(" ")
}
