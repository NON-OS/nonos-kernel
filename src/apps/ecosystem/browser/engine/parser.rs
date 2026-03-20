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
use super::types::{Document, Node, NodeType, Link, Form, FormInput, Image};

pub fn parse_html(html: &str) -> Document {
    let mut title = String::new();
    let root = Node {
        node_type: NodeType::Element("html".to_string()),
        children: Vec::new(),
        attributes: Vec::new(),
    };

    let mut links: Vec<Link> = Vec::new();
    let mut forms: Vec<Form> = Vec::new();
    let mut images: Vec<Image> = Vec::new();
    let mut current_form: Option<Form> = None;
    let mut hidden_classes: Vec<String> = Vec::new();

    let mut stack: Vec<Node> = Vec::new();
    let mut current = Node {
        node_type: NodeType::Element("body".to_string()),
        children: Vec::new(),
        attributes: Vec::new(),
    };

    let mut chars = html.chars().peekable();
    let mut text_buffer = String::new();
    let mut in_head = false;

    while let Some(c) = chars.next() {
        if c == '<' {
            if !text_buffer.trim().is_empty() {
                current.children.push(Node {
                    node_type: NodeType::Text(core::mem::take(&mut text_buffer)),
                    children: Vec::new(),
                    attributes: Vec::new(),
                });
            }
            text_buffer.clear();

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
                let close_tag = tag_content[1..].trim().to_ascii_lowercase();

                if close_tag == "head" {
                    in_head = false;
                    continue;
                }

                if close_tag == "form" {
                    if let Some(form) = current_form.take() {
                        forms.push(form);
                    }
                }

                if let NodeType::Element(ref open_tag) = current.node_type {
                    if open_tag.to_ascii_lowercase() == close_tag {
                        if let Some(mut parent) = stack.pop() {
                            parent.children.push(current);
                            current = parent;
                        }
                    }
                }
                continue;
            }

            let self_closing = tag_content.ends_with('/');
            let tag_content = if self_closing {
                &tag_content[..tag_content.len() - 1]
            } else {
                &tag_content
            };

            let parts: Vec<&str> = tag_content.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let tag_name = parts[0].to_ascii_lowercase();
            let mut attributes = Vec::new();

            for part in parts.iter().skip(1) {
                if let Some(eq_pos) = part.find('=') {
                    let name = &part[..eq_pos];
                    let value = part[eq_pos + 1..].trim_matches(|c| c == '"' || c == '\'');
                    attributes.push((String::from(name), String::from(value)));
                }
            }

            let new_node = Node {
                node_type: NodeType::Element(tag_name.clone()),
                children: Vec::new(),
                attributes: attributes.clone(),
            };

            match tag_name.as_str() {
                "head" => {
                    in_head = true;
                    continue;
                }

                "title" => {
                    while let Some(&tc) = chars.peek() {
                        if tc == '<' {
                            break;
                        }
                        if let Some(ch) = chars.next() {
                            title.push(ch);
                        }
                    }
                    while let Some(&c) = chars.peek() {
                        if c == '>' {
                            break;
                        }
                        chars.next();
                    }
                    chars.next();
                }

                // Raw-text elements: skip to closing tag, discard content.
                // These must never produce Text nodes in the DOM.
                "script" | "noscript" => {
                    let close_pattern = alloc::format!("</{}>", tag_name);
                    let mut scan_buf = String::new();
                    let mut found = false;
                    while let Some(ch) = chars.next() {
                        scan_buf.push(ch);
                        if scan_buf.len() >= close_pattern.len() {
                            let tail_start = scan_buf.len() - close_pattern.len();
                            if scan_buf[tail_start..].eq_ignore_ascii_case(&close_pattern) {
                                found = true;
                                break;
                            }
                        }
                    }
                    if !found {
                        // Malformed HTML — no closing tag. Content already consumed, nothing to push.
                    }
                }

                // <style>: extract CSS content, parse for .class { display: none }, then discard.
                "style" => {
                    let close_pattern = alloc::format!("</{}>", tag_name);
                    let mut css_buf = String::new();
                    let mut found = false;
                    while let Some(ch) = chars.next() {
                        css_buf.push(ch);
                        if css_buf.len() >= close_pattern.len() {
                            let tail_start = css_buf.len() - close_pattern.len();
                            if css_buf[tail_start..].eq_ignore_ascii_case(&close_pattern) {
                                // Trim off the closing tag from the CSS source
                                css_buf.truncate(tail_start);
                                found = true;
                                break;
                            }
                        }
                    }
                    if found {
                        parse_hidden_classes(&css_buf, &mut hidden_classes);
                    }
                }

                // Inside <head>, skip everything except title/script/style
                // which are handled above.
                _ if in_head => {
                    continue;
                }

                "a" => {
                    let href = attributes
                        .iter()
                        .find(|(n, _)| n == "href")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    let rel = attributes
                        .iter()
                        .find(|(n, _)| n == "rel")
                        .map(|(_, v)| v.clone());

                    links.push(Link {
                        href,
                        text: String::new(),
                        rel,
                    });

                    stack.push(current);
                    current = new_node;
                }

                "img" => {
                    let src = attributes
                        .iter()
                        .find(|(n, _)| n == "src")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    let alt = attributes
                        .iter()
                        .find(|(n, _)| n == "alt")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    let width = attributes
                        .iter()
                        .find(|(n, _)| n == "width")
                        .and_then(|(_, v)| v.parse().ok());
                    let height = attributes
                        .iter()
                        .find(|(n, _)| n == "height")
                        .and_then(|(_, v)| v.parse().ok());

                    images.push(Image {
                        src,
                        alt,
                        width,
                        height,
                    });
                    current.children.push(new_node);
                }

                "form" => {
                    let action = attributes
                        .iter()
                        .find(|(n, _)| n == "action")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    let method = attributes
                        .iter()
                        .find(|(n, _)| n == "method")
                        .map(|(_, v)| v.to_string())
                        .unwrap_or_else(|| "GET".to_string());

                    current_form = Some(Form {
                        action,
                        method,
                        inputs: Vec::new(),
                    });

                    stack.push(current);
                    current = new_node;
                }

                "input" => {
                    let name = attributes
                        .iter()
                        .find(|(n, _)| n == "name")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    let input_type = attributes
                        .iter()
                        .find(|(n, _)| n == "type")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_else(|| "text".to_string());
                    let value = attributes
                        .iter()
                        .find(|(n, _)| n == "value")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    let placeholder = attributes
                        .iter()
                        .find(|(n, _)| n == "placeholder")
                        .map(|(_, v)| v.clone());

                    if let Some(ref mut form) = current_form {
                        form.inputs.push(FormInput {
                            name: name.clone(),
                            input_type,
                            value,
                            placeholder,
                        });
                    }
                    current.children.push(new_node);
                }

                "br" | "hr" | "meta" | "link" => {
                    current.children.push(new_node);
                }

                _ => {
                    if !self_closing {
                        stack.push(current);
                        current = new_node;
                    } else {
                        current.children.push(new_node);
                    }
                }
            }
        } else if !in_head {
            text_buffer.push(c);
        }
    }

    if !text_buffer.trim().is_empty() {
        current.children.push(Node {
            node_type: NodeType::Text(text_buffer),
            children: Vec::new(),
            attributes: Vec::new(),
        });
    }

    while let Some(mut parent) = stack.pop() {
        parent.children.push(current);
        current = parent;
    }

    let mut final_root = root;
    final_root.children.push(current);

    Document {
        title,
        root: final_root,
        links,
        forms,
        images,
        hidden_classes,
    }
}

pub fn get_attribute(node: &Node, name: &str) -> Option<String> {
    node.attributes
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
}

pub fn extract_text(node: &Node) -> String {
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

/// Parse CSS text for simple `.class { display: none }` rules.
/// Populates `hidden` with class names that should be hidden.
fn parse_hidden_classes(css: &str, hidden: &mut Vec<String>) {
    let css_lower = css.to_ascii_lowercase();
    let bytes = css_lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Look for '.' indicating a class selector
        if bytes[i] == b'.' {
            i += 1;
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b'_') {
                i += 1;
            }
            if i > start {
                let class_name = &css_lower[start..i];
                // Skip whitespace, look for '{'
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'{' {
                    i += 1;
                    // Collect the block content up to '}'
                    let block_start = i;
                    while i < bytes.len() && bytes[i] != b'}' {
                        i += 1;
                    }
                    let block = &css_lower[block_start..i];
                    // Check if block contains "display" + "none"
                    if (block.contains("display") && block.contains("none"))
                        || (block.contains("visibility") && block.contains("hidden"))
                    {
                        hidden.push(String::from(class_name));
                    }
                    if i < bytes.len() {
                        i += 1; // skip '}'
                    }
                }
            }
        } else {
            i += 1;
        }
    }
}
