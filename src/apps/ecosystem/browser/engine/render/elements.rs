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

use alloc::string::String;
use crate::apps::ecosystem::browser::engine::types::{Node, RenderElement, RenderContent, RenderLine, TextAlign};
use crate::apps::ecosystem::browser::engine::parser::{get_attribute, extract_text};
use super::context::RenderContext;

pub(super) fn render_link(ctx: &mut RenderContext, node: &Node) {
    let href = get_attribute(node, "href").unwrap_or_default();
    let link_text = extract_text(node);
    let link_width = (link_text.len() as u32) * ctx.char_width;

    if ctx.current_x + link_width > ctx.usable_width && ctx.current_x > 0 { ctx.flush_line(); }

    ctx.links.push((ctx.margin + ctx.current_x, ctx.current_y, link_width, ctx.line_height, href.clone()));
    ctx.current_line_elements.push(RenderElement {
        x: ctx.margin + ctx.current_x,
        width: link_width + ctx.char_width,
        content: RenderContent::Link { text: alloc::format!("{} ", link_text), href },
    });
    ctx.current_x += link_width + ctx.char_width;
}

pub(super) fn render_image(ctx: &mut RenderContext, node: &Node) {
    let alt = get_attribute(node, "alt").unwrap_or_default();
    let src = get_attribute(node, "src").unwrap_or_default();
    let attr_width: u32 = get_attribute(node, "width").and_then(|w| w.parse().ok()).unwrap_or(0);
    let attr_height: u32 = get_attribute(node, "height").and_then(|h| h.parse().ok()).unwrap_or(0);
    if ctx.current_x > 0 { ctx.flush_line(); }

    // Try to load and decode the image
    if !src.is_empty() && !ctx.base_url.is_empty() {
        if let Some(data) = crate::apps::ecosystem::browser::engine::image_loader::load_image(&src, &ctx.base_url) {
            let img_w = if attr_width > 0 { attr_width } else { data.width }.min(ctx.usable_width);
            let img_h = if attr_height > 0 { attr_height } else { data.height };
            ctx.lines.push(RenderLine {
                y: ctx.current_y,
                elements: alloc::vec![RenderElement {
                    x: aligned_x(ctx, img_w), width: img_w,
                    content: RenderContent::DecodedImage { data },
                }],
            });
            ctx.current_y += img_h;
            return;
        }
    }

    // Fallback: placeholder
    let width = if attr_width > 0 { attr_width } else { 200 };
    let height = if attr_height > 0 { attr_height } else { 20 };
    let label = if alt.is_empty() { alloc::format!("[IMG {}x{}]", width, height) }
                else { alloc::format!("[IMG {}x{}: {}]", width, height, alt) };
    let label_width = (label.len() as u32) * ctx.char_width;
    let display_width = label_width.max(width).min(ctx.usable_width);
    let resolved_src = if !src.is_empty() && !ctx.base_url.is_empty() {
        crate::apps::ecosystem::browser::engine::image_loader::resolve_url(&src, &ctx.base_url).unwrap_or_default()
    } else { String::new() };
    ctx.lines.push(RenderLine {
        y: ctx.current_y,
        elements: alloc::vec![RenderElement {
            x: aligned_x(ctx, display_width), width: display_width,
            content: RenderContent::Image { alt: label, width: display_width, height, src: resolved_src },
        }],
    });
    ctx.current_y += height;
}

pub(super) fn render_input(ctx: &mut RenderContext, node: &Node) {
    let name = get_attribute(node, "name").unwrap_or_default();
    let input_type = get_attribute(node, "type").unwrap_or_default().to_ascii_lowercase();
    let value = get_attribute(node, "value").unwrap_or_default();

    match input_type.as_str() {
        "hidden" => { return; }
        "submit" => {
            if ctx.current_style.text_align == TextAlign::Center && current_line_has_input(ctx) {
                ctx.flush_line();
            }
            let label = if value.is_empty() { String::from("Submit") } else { value };
            let button_width = (label.len() as u32) * ctx.char_width + 20;
            ctx.current_line_elements.push(RenderElement {
                x: ctx.margin + ctx.current_x, width: button_width,
                content: RenderContent::Button { text: label },
            });
            ctx.current_x += button_width + ctx.char_width;
        }
        _ => {
            let input_width = if input_type == "search" || name == "q" { ctx.usable_width.min(420).max(200) } else { 200u32 };
            ctx.current_line_elements.push(RenderElement {
                x: ctx.margin + ctx.current_x, width: input_width,
                content: RenderContent::Input { name, width: input_width },
            });
            ctx.current_x += input_width + ctx.char_width;
        }
    }
}

fn current_line_has_input(ctx: &RenderContext) -> bool {
    ctx.current_line_elements.iter().any(|elem| matches!(elem.content, RenderContent::Input { .. }))
}

fn aligned_x(ctx: &RenderContext, width: u32) -> u32 {
    match ctx.current_style.text_align {
        TextAlign::Center => ctx.margin + ctx.usable_width.saturating_sub(width) / 2,
        TextAlign::Right => ctx.margin + ctx.usable_width.saturating_sub(width),
        _ => ctx.margin,
    }
}

pub(super) fn render_button(ctx: &mut RenderContext, node: &Node) {
    let text = extract_text(node);
    let button_width = (text.len() as u32) * ctx.char_width + 20;
    ctx.current_line_elements.push(RenderElement {
        x: ctx.margin + ctx.current_x, width: button_width,
        content: RenderContent::Button { text },
    });
    ctx.current_x += button_width + ctx.char_width;
}

pub(super) fn render_select(ctx: &mut RenderContext, node: &Node) {
    let name = get_attribute(node, "name").unwrap_or_default();
    let selected = find_selected_option(node);
    let display_width = ((selected.len() + 4) as u32) * ctx.char_width;
    ctx.current_line_elements.push(RenderElement {
        x: ctx.margin + ctx.current_x, width: display_width,
        content: RenderContent::Select { name, value: selected },
    });
    ctx.current_x += display_width + ctx.char_width;
}

pub(super) fn render_textarea(ctx: &mut RenderContext, node: &Node) {
    let name = get_attribute(node, "name").unwrap_or_default();
    let cols: u32 = get_attribute(node, "cols").and_then(|c| c.parse().ok()).unwrap_or(40);
    let rows: u32 = get_attribute(node, "rows").and_then(|r| r.parse().ok()).unwrap_or(4);
    let width = cols * ctx.char_width;
    let height = rows * ctx.line_height;
    ctx.flush_line();
    ctx.lines.push(RenderLine {
        y: ctx.current_y,
        elements: alloc::vec![RenderElement {
            x: aligned_x(ctx, width), width,
            content: RenderContent::Textarea { name, width, height },
        }],
    });
    ctx.current_y += height;
}

fn find_selected_option(node: &Node) -> String {
    // First look for an <option> with selected attribute
    for child in &node.children {
        if let crate::apps::ecosystem::browser::engine::types::NodeType::Element(ref tag) = child.node_type {
            if tag == "option" {
                if child.attributes.iter().any(|(n, _)| n == "selected") {
                    return extract_text(child);
                }
            }
        }
    }
    // Fall back to first <option>'s text
    for child in &node.children {
        if let crate::apps::ecosystem::browser::engine::types::NodeType::Element(ref tag) = child.node_type {
            if tag == "option" {
                return extract_text(child);
            }
        }
    }
    String::new()
}
