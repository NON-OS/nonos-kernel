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

use super::css::parse_style_classes;
use super::state::ParserState;
use super::tags::{handle_form, handle_image, handle_input, handle_link, parse_attributes};
use crate::apps::ecosystem::browser::engine::types::{Document, Node, NodeType};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Maximum number of tags the parser will process before stopping.
/// Prevents runaway parsing on pathological inputs.
const MAX_TAGS: u32 = 20_000;
const MAX_DOM_DEPTH: usize = 256;
const MAX_STYLE_BYTES: usize = 16 * 1024;
const MAX_TAG_BYTES: usize = 4096;
const MAX_PARSE_MS: u64 = 200;

pub fn parse_html(html: &str) -> Document {
    let mut state = ParserState::new();
    let mut chars = html.chars().peekable();
    let mut tag_count: u32 = 0;
    let mut chars_seen: u32 = 0;
    let parse_start = crate::time::timestamp_millis();
    while let Some(c) = chars.next() {
        chars_seen = chars_seen.wrapping_add(1);
        if chars_seen & 0x3ff == 0 && elapsed_ms_since(parse_start) > MAX_PARSE_MS {
            break;
        }
        if c == '<' {
            tag_count += 1;
            if tag_count > MAX_TAGS {
                break;
            }
            state.flush_text();
            let mut tag_content = String::new();
            while let Some(&tc) = chars.peek() {
                if tc == '>' {
                    chars.next();
                    break;
                }
                if let Some(ch) = chars.next() {
                    tag_content.push(ch);
                }
            }
            if tag_content.starts_with("!--") {
                continue;
            }
            if tag_content.starts_with('/') {
                handle_close_tag(&mut state, &tag_content[1..].trim().to_ascii_lowercase());
                continue;
            }
            process_open_tag(&mut state, &tag_content, &mut chars);
        } else if !state.in_head {
            state.text_buffer.push(c);
        }
    }
    state.flush_text();
    finalize_document(state)
}

fn handle_close_tag(state: &mut ParserState, close_tag: &str) {
    if close_tag == "head" {
        state.in_head = false;
        return;
    }
    if close_tag == "form" {
        if let Some(form) = state.current_form.take() {
            state.forms.push(form);
        }
    }
    if let NodeType::Element(ref open_tag) = state.current.node_type {
        if open_tag.to_ascii_lowercase() == close_tag {
            if let Some(mut parent) = state.stack.pop() {
                parent.children.push(core::mem::replace(&mut state.current, parent.clone()));
                state.current = parent;
            }
        }
    }
}

fn process_open_tag(
    state: &mut ParserState,
    tag_content: &str,
    chars: &mut core::iter::Peekable<core::str::Chars>,
) {
    let self_closing = tag_content.ends_with('/');
    let content = if self_closing { &tag_content[..tag_content.len() - 1] } else { tag_content };
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }
    let tag_name = parts[0].to_ascii_lowercase();
    let attrs = parse_attributes(&parts);
    let node = Node {
        node_type: NodeType::Element(tag_name.clone()),
        children: Vec::new(),
        attributes: attrs.clone(),
    };
    match tag_name.as_str() {
        "head" => {
            state.in_head = true;
        }
        "title" => {
            while let Some(&tc) = chars.peek() {
                if tc == '<' {
                    break;
                }
                if let Some(ch) = chars.next() {
                    state.title.push(ch);
                }
            }
            skip_to_close(chars);
        }
        "script" => {
            skip_raw_text(chars, &tag_name);
        }
        "noscript" => {
            process_noscript(state, chars);
        }
        "style" => {
            process_style(state, chars, &tag_name);
        }
        _ if state.in_head => {}
        "a" => {
            handle_link(state, &attrs, node);
        }
        "img" => {
            handle_image(state, &attrs, node);
        }
        "form" => {
            handle_form(state, &attrs, node);
        }
        "input" => {
            handle_input(state, &attrs, node);
        }
        "br" | "hr" | "meta" | "link" => {
            state.current.children.push(node);
        }
        _ => {
            if !self_closing {
                state.stack.push(core::mem::replace(&mut state.current, node));
            } else {
                state.current.children.push(node);
            }
        }
    }
}

fn skip_to_close(chars: &mut core::iter::Peekable<core::str::Chars>) {
    while let Some(&c) = chars.peek() {
        if c == '>' {
            break;
        }
        chars.next();
    }
    chars.next();
}

fn skip_raw_text(chars: &mut core::iter::Peekable<core::str::Chars>, tag: &str) {
    let pattern = alloc::format!("</{}>", tag);
    let pat_bytes = pattern.as_bytes();
    let mut buf = String::new();
    while let Some(ch) = chars.next() {
        buf.push(ch);
        let bb = buf.as_bytes();
        if bb.len() >= pat_bytes.len()
            && bb[bb.len() - pat_bytes.len()..].eq_ignore_ascii_case(pat_bytes)
        {
            break;
        }
    }
}

fn process_style(
    state: &mut ParserState,
    chars: &mut core::iter::Peekable<core::str::Chars>,
    tag: &str,
) {
    let pattern = alloc::format!("</{}>", tag);
    let pat_bytes = pattern.as_bytes();
    let mut buf = String::new();
    while let Some(ch) = chars.next() {
        buf.push(ch);
        let bb = buf.as_bytes();
        if bb.len() >= pat_bytes.len()
            && bb[bb.len() - pat_bytes.len()..].eq_ignore_ascii_case(pat_bytes)
        {
            buf.truncate(buf.len() - pat_bytes.len());
            parse_style_classes(&buf, &mut state.hidden_classes, &mut state.centered_classes);
            return;
        }
    }
}

fn process_noscript(state: &mut ParserState, chars: &mut core::iter::Peekable<core::str::Chars>) {
    let pattern: &[u8] = b"</noscript>";
    let mut buf = String::new();
    while let Some(ch) = chars.next() {
        buf.push(ch);
        let bb = buf.as_bytes();
        if bb.len() >= pattern.len() && bb[bb.len() - pattern.len()..].eq_ignore_ascii_case(pattern)
        {
            buf.truncate(buf.len() - pattern.len());
            break;
        }
    }
    let inner = buf.trim();
    if !inner.is_empty() {
        if let Some(url) = extract_meta_refresh(inner) {
            state.noscript_redirect = Some(url);
        }
        let mut inner_chars = inner.chars().peekable();
        while let Some(c) = inner_chars.next() {
            if c == '<' {
                state.flush_text();
                let mut tag_content = String::new();
                while let Some(&tc) = inner_chars.peek() {
                    if tc == '>' {
                        inner_chars.next();
                        break;
                    }
                    if let Some(ch) = inner_chars.next() {
                        tag_content.push(ch);
                    }
                }
                if tag_content.starts_with("!--") {
                    continue;
                }
                if tag_content.starts_with('/') {
                    handle_close_tag(state, &tag_content[1..].trim().to_ascii_lowercase());
                    continue;
                }
                process_open_tag(state, &tag_content, &mut inner_chars);
            } else {
                state.text_buffer.push(c);
            }
        }
        state.flush_text();
    }
}

/// Extracts URL from `<meta http-equiv="refresh" content="N;url=...">` inside noscript.
fn extract_meta_refresh(html: &str) -> Option<String> {
    let low = html.to_ascii_lowercase();
    let meta_pos = low.find("<meta")?;
    let end_pos = low[meta_pos..].find('>')? + meta_pos;
    let tag = &low[meta_pos..=end_pos];
    if !tag.contains("http-equiv") || !tag.contains("refresh") {
        return None;
    }
    // Extract content attribute value from original (preserve URL case)
    let orig_tag = &html[meta_pos..=end_pos];
    let content_start = {
        let ct = orig_tag.to_ascii_lowercase();
        let ci = ct.find("content")?;
        let eq = ct[ci..].find('=')? + ci + 1;
        eq
    };
    let rest = orig_tag[content_start..].trim_start();
    let (val_start, quote) = if rest.starts_with('"') {
        (1, Some('"'))
    } else if rest.starts_with('\'') {
        (1, Some('\''))
    } else {
        (0, None)
    };
    let val = &rest[val_start..];
    let val_end = match quote {
        Some(q) => val.find(q).unwrap_or(val.len()),
        None => val.find(|c: char| c == '>' || c.is_whitespace()).unwrap_or(val.len()),
    };
    let content_val = &val[..val_end];
    // Parse "N;url=..." format
    let lower_val = content_val.to_ascii_lowercase();
    if let Some(url_idx) = lower_val.find("url=") {
        let url = content_val[url_idx + 4..].trim();
        if !url.is_empty() {
            return Some(url.to_string());
        }
    }
    None
}

fn finalize_document(mut state: ParserState) -> Document {
    while let Some(mut parent) = state.stack.pop() {
        parent.children.push(state.current);
        state.current = parent;
    }
    let root = Node {
        node_type: NodeType::Element("html".to_string()),
        children: alloc::vec![state.current],
        attributes: Vec::new(),
    };
    Document {
        title: state.title,
        root,
        links: state.links,
        forms: state.forms,
        images: state.images,
        hidden_classes: state.hidden_classes,
        centered_classes: state.centered_classes,
        noscript_redirect: state.noscript_redirect,
    }
}

fn elapsed_ms_since(start: u64) -> u64 {
    crate::time::timestamp_millis().saturating_sub(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_meta_refresh_google_noscript() {
        let html = r#"<meta http-equiv="refresh" content="0;url=?gbv=1">"#;
        let result = extract_meta_refresh(html);
        assert_eq!(result, Some(String::from("?gbv=1")));
    }

    #[test]
    fn test_extract_meta_refresh_absolute_url() {
        let html = r#"<meta http-equiv="refresh" content="5;url=https://example.com/page">"#;
        let result = extract_meta_refresh(html);
        assert_eq!(result, Some(String::from("https://example.com/page")));
    }

    #[test]
    fn test_extract_meta_refresh_no_meta() {
        let html = "<p>Just some text</p>";
        assert!(extract_meta_refresh(html).is_none());
    }

    #[test]
    fn test_extract_meta_refresh_no_refresh() {
        let html = r#"<meta charset="utf-8">"#;
        assert!(extract_meta_refresh(html).is_none());
    }

    #[test]
    fn test_extract_meta_refresh_single_quotes() {
        let html = r#"<meta http-equiv='refresh' content='0;url=/fallback'>"#;
        let result = extract_meta_refresh(html);
        assert_eq!(result, Some(String::from("/fallback")));
    }

    #[test]
    fn test_noscript_redirect_in_document() {
        let html = r#"<html><body><noscript><meta http-equiv="refresh" content="0;url=?gbv=1"></noscript><p>Hello</p></body></html>"#;
        let doc = parse_html(html);
        assert_eq!(doc.noscript_redirect, Some(String::from("?gbv=1")));
    }

    #[test]
    fn test_noscript_no_redirect() {
        let html = "<html><body><noscript><p>Enable JS</p></noscript></body></html>";
        let doc = parse_html(html);
        assert!(doc.noscript_redirect.is_none());
    }
}
