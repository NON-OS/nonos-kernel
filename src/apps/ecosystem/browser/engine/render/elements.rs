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

use crate::apps::ecosystem::browser::engine::types::{Node, RenderElement, RenderContent, RenderLine};
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
    let width: u32 = get_attribute(node, "width").and_then(|w| w.parse().ok()).unwrap_or(200);
    let height: u32 = get_attribute(node, "height").and_then(|h| h.parse().ok()).unwrap_or(20);
    if ctx.current_x > 0 { ctx.flush_line(); }
    let label = if alt.is_empty() { alloc::format!("[IMG {}x{}]", width, height) }
                else { alloc::format!("[IMG {}x{}: {}]", width, height, alt) };
    let label_width = (label.len() as u32) * ctx.char_width;
    let display_width = label_width.max(width).min(ctx.usable_width);
    ctx.lines.push(RenderLine {
        y: ctx.current_y,
        elements: alloc::vec![RenderElement {
            x: ctx.margin, width: display_width,
            content: RenderContent::Image { alt: label, width: display_width, height },
        }],
    });
    ctx.current_y += height;
}

pub(super) fn render_input(ctx: &mut RenderContext, node: &Node) {
    let name = get_attribute(node, "name").unwrap_or_default();
    let input_width = 200u32;
    ctx.current_line_elements.push(RenderElement {
        x: ctx.margin + ctx.current_x, width: input_width,
        content: RenderContent::Input { name, width: input_width },
    });
    ctx.current_x += input_width + ctx.char_width;
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
