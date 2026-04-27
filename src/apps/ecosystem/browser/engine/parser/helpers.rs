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

pub(crate) fn decode_html_entities(input: &str) -> String {
    if !input.as_bytes().contains(&b'&') { return String::from(input); }
    let mut out = String::new();
    let mut rest = input;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after_amp = &rest[pos + 1..];
        if let Some(end) = after_amp.find(';') {
            let entity = &after_amp[..end];
            if let Some(decoded) = decode_entity(entity) {
                out.push_str(&decoded);
                rest = &after_amp[end + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after_amp;
    }
    out.push_str(rest);
    out
}

fn decode_entity(entity: &str) -> Option<String> {
    match entity {
        "amp" => Some(String::from("&")),
        "lt" => Some(String::from("<")),
        "gt" => Some(String::from(">")),
        "quot" => Some(String::from("\"")),
        "apos" => Some(String::from("'")),
        "nbsp" => Some(String::from(" ")),
        "copy" => Some(String::from("(c)")),
        "reg" => Some(String::from("(r)")),
        _ => decode_numeric_entity(entity),
    }
}

fn decode_numeric_entity(entity: &str) -> Option<String> {
    let value = if entity.starts_with("#x") || entity.starts_with("#X") {
        u32::from_str_radix(&entity[2..], 16).ok()?
    } else if let Some(decimal) = entity.strip_prefix('#') {
        decimal.parse::<u32>().ok()?
    } else { return None; };
    let mut out = String::new();
    match value {
        0x09 | 0x0a | 0x0d | 0xa0 => out.push(' '),
        0xa9 => out.push_str("(c)"),
        0xae => out.push_str("(r)"),
        0x20..=0x7e => out.push(core::char::from_u32(value)?),
        _ => out.push('?'),
    }
    Some(out)
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
    decode_html_entities(&out.split_whitespace().collect::<alloc::vec::Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::decode_html_entities;

    #[test]
    fn test_decode_common_entities() {
        assert_eq!(decode_html_entities("A&nbsp;&amp;&copy;&#169;&#x41;"), "A &(c)(c)A");
    }
}
