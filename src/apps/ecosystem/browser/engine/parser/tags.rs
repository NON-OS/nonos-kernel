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

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::apps::ecosystem::browser::engine::types::{Node, Link, Form, FormInput, Image};
use super::helpers::decode_html_entities;
use super::state::ParserState;

pub(super) fn parse_attributes(parts: &[&str]) -> Vec<(String, String)> {
    let mut attributes = Vec::new();
    let mut i = 1; // skip tag name
    while i < parts.len() {
        let part = parts[i];
        if let Some(eq_pos) = part.find('=') {
            let name = &part[..eq_pos];
            let raw_value = &part[eq_pos + 1..];
            // Check if value starts with a quote but doesn't end with one (split mid-quote)
            let starts_quote = raw_value.starts_with('"') || raw_value.starts_with('\'');
            let quote_char = if starts_quote { raw_value.as_bytes()[0] } else { 0 };
            let ends_quote = raw_value.len() > 1 && raw_value.as_bytes()[raw_value.len() - 1] == quote_char;
            if starts_quote && !ends_quote {
                // Rejoin space-split quoted value
                let mut joined = String::from(&raw_value[1..]); // strip opening quote
                i += 1;
                while i < parts.len() {
                    let next = parts[i];
                    joined.push(' ');
                    if next.ends_with(quote_char as char) {
                        joined.push_str(&next[..next.len() - 1]); // strip closing quote
                        break;
                    }
                    joined.push_str(next);
                    i += 1;
                }
                attributes.push((String::from(name), decode_html_entities(&joined)));
            } else {
                let value = raw_value.trim_matches(|c| c == '"' || c == '\'');
                attributes.push((String::from(name), decode_html_entities(value)));
            }
        } else {
            // Boolean attribute (e.g., "selected", "disabled", "checked")
            let name = part.trim_matches(|c: char| c == '"' || c == '\'' || c == '/');
            if !name.is_empty() {
                attributes.push((String::from(name), String::new()));
            }
        }
        i += 1;
    }
    attributes
}

pub(super) fn handle_link(state: &mut ParserState, attrs: &[(String, String)], node: Node) {
    let href = attrs.iter().find(|(n, _)| n == "href").map(|(_, v)| v.clone()).unwrap_or_default();
    let rel = attrs.iter().find(|(n, _)| n == "rel").map(|(_, v)| v.clone());
    state.links.push(Link { href, text: String::new(), rel });
    state.stack.push(core::mem::replace(&mut state.current, node));
}

pub(super) fn handle_image(state: &mut ParserState, attrs: &[(String, String)], node: Node) {
    let src = attrs.iter().find(|(n, _)| n == "src").map(|(_, v)| v.clone()).unwrap_or_default();
    let alt = attrs.iter().find(|(n, _)| n == "alt").map(|(_, v)| v.clone()).unwrap_or_default();
    let width = attrs.iter().find(|(n, _)| n == "width").and_then(|(_, v)| v.parse().ok());
    let height = attrs.iter().find(|(n, _)| n == "height").and_then(|(_, v)| v.parse().ok());
    state.images.push(Image { src, alt, width, height });
    state.current.children.push(node);
}

pub(super) fn handle_form(state: &mut ParserState, attrs: &[(String, String)], node: Node) {
    let action = attrs.iter().find(|(n, _)| n == "action").map(|(_, v)| v.clone()).unwrap_or_default();
    let method = attrs.iter().find(|(n, _)| n == "method").map(|(_, v)| v.to_string()).unwrap_or_else(|| "GET".to_string());
    state.current_form = Some(Form { action, method, inputs: Vec::new() });
    state.stack.push(core::mem::replace(&mut state.current, node));
}

pub(super) fn handle_input(state: &mut ParserState, attrs: &[(String, String)], node: Node) {
    let name = attrs.iter().find(|(n, _)| n == "name").map(|(_, v)| v.clone()).unwrap_or_default();
    let input_type = attrs.iter().find(|(n, _)| n == "type").map(|(_, v)| v.clone()).unwrap_or_else(|| "text".to_string());
    let value = attrs.iter().find(|(n, _)| n == "value").map(|(_, v)| v.clone()).unwrap_or_default();
    let placeholder = attrs.iter().find(|(n, _)| n == "placeholder").map(|(_, v)| v.clone());
    if let Some(ref mut form) = state.current_form {
        form.inputs.push(FormInput { name: name.clone(), input_type, value, placeholder });
    }
    state.current.children.push(node);
}
