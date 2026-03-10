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
