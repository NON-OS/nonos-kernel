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

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct BrowserEngine {
    document: Option<Document>,
    viewport_width: u32,
    viewport_height: u32,
    scroll_x: u32,
    scroll_y: u32,
}

#[derive(Debug, Clone)]
pub struct Document {
    pub title: String,
    pub root: Node,
    pub links: Vec<Link>,
    pub forms: Vec<Form>,
    pub images: Vec<Image>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub node_type: NodeType,
    pub children: Vec<Node>,
    pub attributes: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub enum NodeType {
    Element(String),
    Text(String),
    Comment(String),
}

#[derive(Debug, Clone)]
pub struct Link {
    pub href: String,
    pub text: String,
    pub rel: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub inputs: Vec<FormInput>,
}

#[derive(Debug, Clone)]
pub struct FormInput {
    pub name: String,
    pub input_type: String,
    pub value: String,
    pub placeholder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Image {
    pub src: String,
    pub alt: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RenderLine {
    pub y: u32,
    pub elements: Vec<RenderElement>,
}

#[derive(Debug, Clone)]
pub struct RenderElement {
    pub x: u32,
    pub width: u32,
    pub content: RenderContent,
}

#[derive(Debug, Clone)]
pub enum RenderContent {
    Text { text: String, style: TextStyle },
    Link { text: String, href: String },
    Image { alt: String, width: u32, height: u32 },
    Input { name: String, width: u32 },
    Button { text: String },
    LineBreak,
    HorizontalRule,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TextStyle {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub heading_level: u8,
    pub monospace: bool,
}

#[derive(Debug, Clone)]
pub struct RenderOutput {
    pub lines: Vec<RenderLine>,
    pub total_height: u32,
    pub links: Vec<(u32, u32, u32, u32, String)>,
}

impl BrowserEngine {
    pub fn new(viewport_width: u32, viewport_height: u32) -> Self {
        Self {
            document: None,
            viewport_width,
            viewport_height,
            scroll_x: 0,
            scroll_y: 0,
        }
    }

    pub fn set_viewport(&mut self, width: u32, height: u32) {
        self.viewport_width = width;
        self.viewport_height = height;
    }

    pub fn scroll_to(&mut self, x: u32, y: u32) {
        self.scroll_x = x;
        self.scroll_y = y;
    }

    pub fn scroll_by(&mut self, dx: i32, dy: i32) {
        self.scroll_x = (self.scroll_x as i32 + dx).max(0) as u32;
        self.scroll_y = (self.scroll_y as i32 + dy).max(0) as u32;
    }

    pub fn load_html(&mut self, html: &str) -> &Document {
        let document = parse_html(html);
        self.document = Some(document);
        self.scroll_x = 0;
        self.scroll_y = 0;
        // SAFETY: We just assigned Some(document) above
        match self.document.as_ref() {
            Some(d) => d,
            None => unreachable!(),
        }
    }

    pub fn document(&self) -> Option<&Document> {
        self.document.as_ref()
    }

    pub fn title(&self) -> Option<&str> {
        self.document.as_ref().map(|d| d.title.as_str())
    }
}

pub fn render_page(html: &str, viewport_width: u32) -> RenderOutput {
    let document = parse_html(html);

    let mut lines: Vec<RenderLine> = Vec::new();
    let mut links: Vec<(u32, u32, u32, u32, String)> = Vec::new();
    let mut current_y: u32 = 0;
    let mut current_line_elements: Vec<RenderElement> = Vec::new();
    let mut current_x: u32 = 0;

    let line_height: u32 = 20;
    let char_width: u32 = 8;
    let margin: u32 = 10;
    let usable_width = viewport_width.saturating_sub(margin * 2);

    let mut style_stack: Vec<TextStyle> = Vec::new();
    let mut current_style = TextStyle::default();

    let mut node_queue: VecDeque<(&Node, bool)> = VecDeque::new();
    node_queue.push_back((&document.root, false));

    while let Some((node, is_closing)) = node_queue.pop_front() {
        if is_closing {
            if let NodeType::Element(tag) = &node.node_type {
                match tag.as_str() {
                    "b" | "strong" => {
                        if let Some(s) = style_stack.pop() {
                            current_style = s;
                        }
                    }
                    "i" | "em" => {
                        if let Some(s) = style_stack.pop() {
                            current_style = s;
                        }
                    }
                    "u" => {
                        if let Some(s) = style_stack.pop() {
                            current_style = s;
                        }
                    }
                    "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                        if let Some(s) = style_stack.pop() {
                            current_style = s;
                        }
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height * 2;
                            current_x = 0;
                        }
                    }
                    "code" | "pre" => {
                        if let Some(s) = style_stack.pop() {
                            current_style = s;
                        }
                    }
                    "p" | "div" | "li" | "tr" => {
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }

        match &node.node_type {
            NodeType::Text(text) => {
                let text = text.trim();
                if text.is_empty() {
                    continue;
                }

                let words: Vec<&str> = text.split_whitespace().collect();
                for word in words {
                    let word_width = (word.len() as u32) * char_width;

                    if current_x + word_width > usable_width && current_x > 0 {
                        lines.push(RenderLine {
                            y: current_y,
                            elements: core::mem::take(&mut current_line_elements),
                        });
                        current_y += line_height;
                        current_x = 0;
                    }

                    current_line_elements.push(RenderElement {
                        x: margin + current_x,
                        width: word_width + char_width,
                        content: RenderContent::Text {
                            text: alloc::format!("{} ", word),
                            style: current_style,
                        },
                    });
                    current_x += word_width + char_width;
                }
            }

            NodeType::Element(tag) => {
                match tag.as_str() {
                    "br" => {
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                        }
                        current_y += line_height;
                        current_x = 0;
                    }

                    "hr" => {
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                        }
                        lines.push(RenderLine {
                            y: current_y,
                            elements: alloc::vec![RenderElement {
                                x: margin,
                                width: usable_width,
                                content: RenderContent::HorizontalRule,
                            }],
                        });
                        current_y += line_height;
                        current_x = 0;
                    }

                    "b" | "strong" => {
                        style_stack.push(current_style);
                        current_style.bold = true;
                    }

                    "i" | "em" => {
                        style_stack.push(current_style);
                        current_style.italic = true;
                    }

                    "u" => {
                        style_stack.push(current_style);
                        current_style.underline = true;
                    }

                    "h1" => {
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }
                        style_stack.push(current_style);
                        current_style.heading_level = 1;
                        current_style.bold = true;
                    }

                    "h2" => {
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }
                        style_stack.push(current_style);
                        current_style.heading_level = 2;
                        current_style.bold = true;
                    }

                    "h3" | "h4" | "h5" | "h6" => {
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }
                        style_stack.push(current_style);
                        current_style.heading_level = tag.as_bytes()[1] - b'0';
                        current_style.bold = true;
                    }

                    "code" | "pre" => {
                        style_stack.push(current_style);
                        current_style.monospace = true;
                    }

                    "a" => {
                        let href = get_attribute(node, "href").unwrap_or_default();
                        let link_text = extract_text(node);

                        let link_width = (link_text.len() as u32) * char_width;

                        if current_x + link_width > usable_width && current_x > 0 {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }

                        links.push((
                            margin + current_x,
                            current_y,
                            link_width,
                            line_height,
                            href.clone(),
                        ));

                        current_line_elements.push(RenderElement {
                            x: margin + current_x,
                            width: link_width + char_width,
                            content: RenderContent::Link {
                                text: alloc::format!("{} ", link_text),
                                href,
                            },
                        });
                        current_x += link_width + char_width;
                        continue;
                    }

                    "img" => {
                        let alt = get_attribute(node, "alt").unwrap_or_default();
                        let width: u32 = get_attribute(node, "width")
                            .and_then(|w| w.parse().ok())
                            .unwrap_or(100);
                        let height: u32 = get_attribute(node, "height")
                            .and_then(|h| h.parse().ok())
                            .unwrap_or(100);

                        if current_x > 0 {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }

                        lines.push(RenderLine {
                            y: current_y,
                            elements: alloc::vec![RenderElement {
                                x: margin,
                                width,
                                content: RenderContent::Image { alt, width, height },
                            }],
                        });
                        current_y += height;
                        continue;
                    }

                    "input" => {
                        let name = get_attribute(node, "name").unwrap_or_default();
                        let input_width = 200u32;

                        current_line_elements.push(RenderElement {
                            x: margin + current_x,
                            width: input_width,
                            content: RenderContent::Input { name, width: input_width },
                        });
                        current_x += input_width + char_width;
                        continue;
                    }

                    "button" => {
                        let text = extract_text(node);
                        let button_width = (text.len() as u32) * char_width + 20;

                        current_line_elements.push(RenderElement {
                            x: margin + current_x,
                            width: button_width,
                            content: RenderContent::Button { text },
                        });
                        current_x += button_width + char_width;
                        continue;
                    }

                    "p" | "div" | "li" => {
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }
                    }

                    "ul" | "ol" => {
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }
                    }

                    _ => {}
                }

                for child in node.children.iter().rev() {
                    node_queue.push_front((child, false));
                }
                node_queue.push_front((node, true));
                continue;
            }

            NodeType::Comment(_) => {}
        }
    }

    if !current_line_elements.is_empty() {
        lines.push(RenderLine {
            y: current_y,
            elements: current_line_elements,
        });
        current_y += line_height;
    }

    RenderOutput {
        lines,
        total_height: current_y,
        links,
    }
}

fn parse_html(html: &str) -> Document {
    let mut title = String::new();
    let mut root = Node {
        node_type: NodeType::Element("html".to_string()),
        children: Vec::new(),
        attributes: Vec::new(),
    };

    let mut links: Vec<Link> = Vec::new();
    let mut forms: Vec<Form> = Vec::new();
    let mut images: Vec<Image> = Vec::new();
    let mut current_form: Option<Form> = None;

    let mut stack: Vec<Node> = Vec::new();
    let mut current = Node {
        node_type: NodeType::Element("body".to_string()),
        children: Vec::new(),
        attributes: Vec::new(),
    };

    let mut chars = html.chars().peekable();
    let mut text_buffer = String::new();

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
        } else {
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

    root.children.push(current);

    Document {
        title,
        root,
        links,
        forms,
        images,
    }
}

fn get_attribute(node: &Node, name: &str) -> Option<String> {
    node.attributes
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
}

fn extract_text(node: &Node) -> String {
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

pub fn render_to_lines(html: &str) -> Vec<String> {
    let output = render_page(html, 800);
    let mut result: Vec<String> = Vec::new();

    for line in output.lines {
        let mut line_text = String::new();
        for element in line.elements {
            match element.content {
                RenderContent::Text { text, .. } => {
                    line_text.push_str(&text);
                }
                RenderContent::Link { text, href } => {
                    line_text.push_str(&text);
                    line_text.push_str(" [");
                    line_text.push_str(&href);
                    line_text.push(']');
                }
                RenderContent::Image { alt, .. } => {
                    line_text.push_str("[IMG: ");
                    line_text.push_str(&alt);
                    line_text.push(']');
                }
                RenderContent::Input { name, .. } => {
                    line_text.push_str("[INPUT: ");
                    line_text.push_str(&name);
                    line_text.push(']');
                }
                RenderContent::Button { text } => {
                    line_text.push_str("[BTN: ");
                    line_text.push_str(&text);
                    line_text.push(']');
                }
                RenderContent::LineBreak => {}
                RenderContent::HorizontalRule => {
                    line_text.push_str("────────────────────────────────");
                }
            }
        }
        if !line_text.trim().is_empty() {
            result.push(line_text);
        }
    }

    if result.is_empty() {
        let plain_text: String = html.chars()
            .filter(|c| !c.is_control() || *c == '\n')
            .collect();

        for line in plain_text.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                result.push(String::from(trimmed));
            }
        }
    }

    result
}
