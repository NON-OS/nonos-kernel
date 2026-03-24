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
use crate::apps::ecosystem::browser::engine::types::{Document, Node, NodeType};
use super::state::ParserState;
use super::tags::{parse_attributes, handle_link, handle_image, handle_form, handle_input};
use super::css::parse_hidden_classes;

pub fn parse_html(html: &str) -> Document {
    let mut state = ParserState::new();
    let mut chars = html.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '<' {
            state.flush_text();
            let mut tag_content = String::new();
            while let Some(&tc) = chars.peek() { if tc == '>' { chars.next(); break; } if let Some(ch) = chars.next() { tag_content.push(ch); } }
            if tag_content.starts_with("!--") { continue; }
            if tag_content.starts_with('/') { handle_close_tag(&mut state, &tag_content[1..].trim().to_ascii_lowercase()); continue; }
            process_open_tag(&mut state, &tag_content, &mut chars);
        } else if !state.in_head { state.text_buffer.push(c); }
    }
    state.flush_text();
    finalize_document(state)
}

fn handle_close_tag(state: &mut ParserState, close_tag: &str) {
    if close_tag == "head" { state.in_head = false; return; }
    if close_tag == "form" { if let Some(form) = state.current_form.take() { state.forms.push(form); } }
    if let NodeType::Element(ref open_tag) = state.current.node_type {
        if open_tag.to_ascii_lowercase() == close_tag {
            if let Some(mut parent) = state.stack.pop() { parent.children.push(core::mem::replace(&mut state.current, parent.clone())); state.current = parent; }
        }
    }
}

fn process_open_tag(state: &mut ParserState, tag_content: &str, chars: &mut core::iter::Peekable<core::str::Chars>) {
    let self_closing = tag_content.ends_with('/');
    let content = if self_closing { &tag_content[..tag_content.len() - 1] } else { tag_content };
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.is_empty() { return; }
    let tag_name = parts[0].to_ascii_lowercase();
    let attrs = parse_attributes(&parts);
    let node = Node { node_type: NodeType::Element(tag_name.clone()), children: Vec::new(), attributes: attrs.clone() };
    match tag_name.as_str() {
        "head" => { state.in_head = true; }
        "title" => { while let Some(&tc) = chars.peek() { if tc == '<' { break; } if let Some(ch) = chars.next() { state.title.push(ch); } } skip_to_close(chars); }
        "script" => { skip_raw_text(chars, &tag_name); }
        "noscript" => { process_noscript(state, chars); }
        "style" => { process_style(state, chars, &tag_name); }
        _ if state.in_head => {}
        "a" => { handle_link(state, &attrs, node); }
        "img" => { handle_image(state, &attrs, node); }
        "form" => { handle_form(state, &attrs, node); }
        "input" => { handle_input(state, &attrs, node); }
        "br" | "hr" | "meta" | "link" => { state.current.children.push(node); }
        _ => { if !self_closing { state.stack.push(core::mem::replace(&mut state.current, node)); } else { state.current.children.push(node); } }
    }
}

fn skip_to_close(chars: &mut core::iter::Peekable<core::str::Chars>) { while let Some(&c) = chars.peek() { if c == '>' { break; } chars.next(); } chars.next(); }

fn skip_raw_text(chars: &mut core::iter::Peekable<core::str::Chars>, tag: &str) {
    let pattern = alloc::format!("</{}>", tag); let mut buf = String::new();
    while let Some(ch) = chars.next() { buf.push(ch); if buf.len() >= pattern.len() && buf[buf.len() - pattern.len()..].eq_ignore_ascii_case(&pattern) { break; } }
}

fn process_style(state: &mut ParserState, chars: &mut core::iter::Peekable<core::str::Chars>, tag: &str) {
    let pattern = alloc::format!("</{}>", tag); let mut buf = String::new();
    while let Some(ch) = chars.next() { buf.push(ch); if buf.len() >= pattern.len() && buf[buf.len() - pattern.len()..].eq_ignore_ascii_case(&pattern) { buf.truncate(buf.len() - pattern.len()); parse_hidden_classes(&buf, &mut state.hidden_classes); return; } }
}

fn process_noscript(state: &mut ParserState, chars: &mut core::iter::Peekable<core::str::Chars>) {
    let pattern = "</noscript>"; let mut buf = String::new();
    while let Some(ch) = chars.next() { buf.push(ch); if buf.len() >= pattern.len() && buf[buf.len() - pattern.len()..].eq_ignore_ascii_case(pattern) { buf.truncate(buf.len() - pattern.len()); break; } }
    let inner = buf.trim();
    if !inner.is_empty() {
        let mut inner_chars = inner.chars().peekable();
        while let Some(c) = inner_chars.next() {
            if c == '<' {
                state.flush_text();
                let mut tag_content = String::new();
                while let Some(&tc) = inner_chars.peek() { if tc == '>' { inner_chars.next(); break; } if let Some(ch) = inner_chars.next() { tag_content.push(ch); } }
                if tag_content.starts_with("!--") || tag_content.starts_with('/') { continue; }
                process_open_tag(state, &tag_content, &mut inner_chars);
            } else { state.text_buffer.push(c); }
        }
        state.flush_text();
    }
}

fn finalize_document(mut state: ParserState) -> Document {
    while let Some(mut parent) = state.stack.pop() { parent.children.push(state.current); state.current = parent; }
    let root = Node { node_type: NodeType::Element("html".to_string()), children: alloc::vec![state.current], attributes: Vec::new() };
    Document { title: state.title, root, links: state.links, forms: state.forms, images: state.images, hidden_classes: state.hidden_classes }
}
