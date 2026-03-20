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
use alloc::string::String;
use alloc::vec::Vec;
use super::types::{Node, NodeType, RenderLine, RenderElement, RenderContent, TextStyle, RenderOutput};
use super::parser::{parse_html, get_attribute, extract_text};

/// Returns true for HTML elements that are block-level (force line break before/after).
fn is_block_element(tag: &str) -> bool {
    matches!(tag,
        "p" | "div" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
        | "ul" | "ol" | "li" | "table" | "tr" | "blockquote"
        | "pre" | "form" | "fieldset" | "address" | "dl" | "dt" | "dd"
        | "nav" | "header" | "footer" | "section" | "article" | "aside" | "main"
        | "figure" | "figcaption" | "details" | "summary"
    )
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

    // List context for bullet / numbering
    enum ListCtx { Unordered, Ordered(u32) }
    let mut list_stack: Vec<ListCtx> = Vec::new();

    // Blockquote indentation level
    let mut indent_level: u32 = 0;
    let indent_px: u32 = 30;

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
                    // <th> pushes bold on open — pop it on close
                    "th" => {
                        if let Some(s) = style_stack.pop() {
                            current_style = s;
                        }
                    }
                    "blockquote" => {
                        if !current_line_elements.is_empty() {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }
                        if indent_level > 0 {
                            indent_level -= 1;
                        }
                    }
                    "p" | "div" | "li" | "tr" | "table" | "nav" | "header"
                    | "footer" | "section" | "article" | "aside" | "main"
                    | "figure" | "details" => {
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
                        if let Some(_) = list_stack.pop() {}
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

                let extra_margin = indent_level * indent_px;
                let words: Vec<&str> = text.split_whitespace().collect();
                for word in words {
                    let word_width = (word.len() as u32) * char_width;

                    if current_x + word_width > usable_width.saturating_sub(extra_margin) && current_x > 0 {
                        lines.push(RenderLine {
                            y: current_y,
                            elements: core::mem::take(&mut current_line_elements),
                        });
                        current_y += line_height;
                        current_x = 0;
                    }

                    current_line_elements.push(RenderElement {
                        x: margin + extra_margin + current_x,
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
                // --- Inline style="display:none" check ---
                // Skip this element and all its children if hidden.
                if node.attributes.iter().any(|(n, v)| {
                    n == "style" && {
                        let low = v.to_ascii_lowercase();
                        low.contains("display:none") || low.contains("display: none")
                            || low.contains("visibility:hidden") || low.contains("visibility: hidden")
                    }
                }) {
                    continue;
                }

                // --- CSS class-based display:none ---
                if !document.hidden_classes.is_empty() {
                    if let Some(cls_attr) = get_attribute(node, "class") {
                        let dominated = cls_attr.split_whitespace().any(|cls| {
                            document.hidden_classes.iter().any(|h| h == cls)
                        });
                        if dominated {
                            continue;
                        }
                    }
                }

                // --- Block-level flush: line break before block elements ---
                if is_block_element(tag) && !current_line_elements.is_empty() {
                    lines.push(RenderLine {
                        y: current_y,
                        elements: core::mem::take(&mut current_line_elements),
                    });
                    current_y += line_height;
                    current_x = 0;
                }

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
                        // Block flush already done by is_block_element() above
                        style_stack.push(current_style);
                        current_style.heading_level = 1;
                        current_style.bold = true;
                    }

                    "h2" => {
                        // Block flush already done by is_block_element() above
                        style_stack.push(current_style);
                        current_style.heading_level = 2;
                        current_style.bold = true;
                    }

                    "h3" | "h4" | "h5" | "h6" => {
                        // Block flush already done by is_block_element() above
                        style_stack.push(current_style);
                        current_style.heading_level = tag.as_bytes()[1] - b'0';
                        current_style.bold = true;
                    }

                    "code" | "pre" => {
                        style_stack.push(current_style);
                        current_style.monospace = true;
                        current_style.bg_color = Some(0xFF2C2C2E);
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
                            .unwrap_or(200);
                        let height: u32 = get_attribute(node, "height")
                            .and_then(|h| h.parse().ok())
                            .unwrap_or(20);

                        if current_x > 0 {
                            lines.push(RenderLine {
                                y: current_y,
                                elements: core::mem::take(&mut current_line_elements),
                            });
                            current_y += line_height;
                            current_x = 0;
                        }

                        // Render bordered placeholder with dimensions and alt text
                        let label = if alt.is_empty() {
                            alloc::format!("[IMG {}x{}]", width, height)
                        } else {
                            alloc::format!("[IMG {}x{}: {}]", width, height, alt)
                        };
                        let label_width = (label.len() as u32) * char_width;
                        let display_width = label_width.max(width).min(usable_width);

                        lines.push(RenderLine {
                            y: current_y,
                            elements: alloc::vec![RenderElement {
                                x: margin,
                                width: display_width,
                                content: RenderContent::Image { alt: label, width: display_width, height },
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

                    "p" | "div" => {
                        // Block flush already handled by is_block_element() above
                    }

                    "li" => {
                        // Block flush already done by is_block_element() above
                        // Prepend bullet / number
                        let prefix = match list_stack.last_mut() {
                            Some(ListCtx::Unordered) => alloc::format!("\u{2022} "),
                            Some(ListCtx::Ordered(n)) => {
                                let s = alloc::format!("{}. ", *n);
                                *n += 1;
                                s
                            }
                            None => alloc::format!("\u{2022} "),
                        };
                        let pw = (prefix.len() as u32) * char_width;
                        current_line_elements.push(RenderElement {
                            x: margin + current_x,
                            width: pw,
                            content: RenderContent::Text {
                                text: prefix,
                                style: current_style,
                            },
                        });
                        current_x += pw;
                    }

                    "ul" => {
                        // Block flush already done by is_block_element() above
                        list_stack.push(ListCtx::Unordered);
                    }

                    "ol" => {
                        // Block flush already done by is_block_element() above
                        list_stack.push(ListCtx::Ordered(1));
                    }

                    // Blockquote: increase indent
                    "blockquote" => {
                        // Block flush already done by is_block_element() above
                        indent_level += 1;
                    }

                    // Select: render first option as placeholder
                    "select" => {
                        let first_option = node.children.iter()
                            .find(|c| matches!(&c.node_type, NodeType::Element(t) if t == "option"))
                            .map(|c| extract_text(c))
                            .unwrap_or_else(|| String::from("..."));
                        let label = alloc::format!("[v {}] ", first_option);
                        let lw = (label.len() as u32) * char_width;
                        current_line_elements.push(RenderElement {
                            x: margin + current_x,
                            width: lw,
                            content: RenderContent::Input {
                                name: get_attribute(node, "name").unwrap_or_default(),
                                width: lw,
                            },
                        });
                        current_x += lw + char_width;
                        continue;
                    }

                    // Textarea: render as multi-line input placeholder
                    "textarea" => {
                        let placeholder = get_attribute(node, "placeholder")
                            .unwrap_or_else(|| String::from("..."));
                        let label = alloc::format!("[TEXTAREA: {}] ", placeholder);
                        let lw = (label.len() as u32) * char_width;
                        current_line_elements.push(RenderElement {
                            x: margin + current_x,
                            width: lw,
                            content: RenderContent::Input {
                                name: get_attribute(node, "name").unwrap_or_default(),
                                width: lw,
                            },
                        });
                        current_x += lw + char_width;
                        continue;
                    }

                    // Table: block element (flush done above)
                    "table" => {
                        // Block flush already done by is_block_element() above
                    }

                    // Table row: new line per row (flush done above)
                    "tr" => {
                        // Block flush already done by is_block_element() above
                    }

                    // Table header cell: tab separator + bold text
                    "th" => {
                        if current_x > 0 {
                            let sep_width = char_width * 4;
                            current_line_elements.push(RenderElement {
                                x: margin + current_x,
                                width: sep_width,
                                content: RenderContent::Text {
                                    text: String::from("    "),
                                    style: TextStyle::default(),
                                },
                            });
                            current_x += sep_width;
                        }
                        style_stack.push(current_style);
                        current_style.bold = true;
                    }

                    // Table cell: insert tab separator between cells
                    "td" => {
                        if current_x > 0 {
                            let sep_width = char_width * 4;
                            current_line_elements.push(RenderElement {
                                x: margin + current_x,
                                width: sep_width,
                                content: RenderContent::Text {
                                    text: String::from("    "),
                                    style: TextStyle::default(),
                                },
                            });
                            current_x += sep_width;
                        }
                    }

                    // Passthrough containers
                    "thead" | "tbody" | "tfoot" | "nav" | "header"
                    | "footer" | "section" | "article" | "aside" | "main"
                    | "span" | "figure" | "figcaption" | "details" | "summary" => {}

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

pub fn render_to_lines(html: &str) -> Vec<String> {
    let (lines, _) = render_to_lines_with_links(html);
    lines
}

pub fn render_to_lines_with_links(html: &str) -> (Vec<String>, Vec<(usize, u32, u32, String)>) {
    let output = render_page(html, 800);
    let mut result: Vec<String> = Vec::new();
    let mut links: Vec<(usize, u32, u32, String)> = Vec::new();

    for line in output.lines {
        let mut line_text = String::new();
        let mut current_char_pos: u32 = 0;

        for element in line.elements {
            match element.content {
                RenderContent::Text { ref text, style } => {
                    if style.heading_level > 0 {
                        line_text.push_str("## ");
                        current_char_pos += 3;
                    }
                    if style.bold {
                        line_text.push_str("**");
                        current_char_pos += 2;
                    }
                    if style.monospace {
                        line_text.push('`');
                        current_char_pos += 1;
                    }
                    line_text.push_str(text);
                    current_char_pos += text.len() as u32;
                    if style.monospace {
                        line_text.push('`');
                        current_char_pos += 1;
                    }
                    if style.bold {
                        line_text.push_str("**");
                        current_char_pos += 2;
                    }
                }
                RenderContent::Link { ref text, ref href } => {
                    let link_start = current_char_pos;
                    line_text.push_str(text);
                    current_char_pos += text.len() as u32;
                    if !href.is_empty() {
                        line_text.push_str(" [");
                        line_text.push_str(href);
                        line_text.push(']');
                        current_char_pos += 3 + href.len() as u32;
                        let link_end = current_char_pos;
                        let line_idx = result.len();
                        links.push((line_idx, link_start * 8 + 16, link_end * 8 + 16, href.clone()));
                    }
                }
                RenderContent::Image { ref alt, .. } => {
                    line_text.push_str("[IMG: ");
                    if !alt.is_empty() {
                        line_text.push_str(alt);
                    } else {
                        line_text.push_str("image");
                    }
                    line_text.push(']');
                    current_char_pos += if alt.is_empty() { 12 } else { 7 + alt.len() as u32 };
                }
                RenderContent::Input { ref name, .. } => {
                    line_text.push_str("[INPUT: ");
                    line_text.push_str(name);
                    line_text.push(']');
                    current_char_pos += 9 + name.len() as u32;
                }
                RenderContent::Button { ref text } => {
                    line_text.push_str("[BTN: ");
                    line_text.push_str(text);
                    line_text.push(']');
                    current_char_pos += 7 + text.len() as u32;
                }
                RenderContent::LineBreak => {}
                RenderContent::HorizontalRule => {
                    line_text.push_str("----------------------------------------");
                    current_char_pos += 40;
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

    (result, links)
}
