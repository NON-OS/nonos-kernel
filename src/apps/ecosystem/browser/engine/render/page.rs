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

use super::block::is_block_element;
use super::closing::handle_closing_tag;
use super::context::RenderContext;
use super::css::apply_inline_css;
use super::elements::{
    render_button, render_image, render_input, render_link, render_select, render_textarea,
};
use super::text::render_text;
use crate::apps::ecosystem::browser::engine::parser::{get_attribute, parse_html};
use crate::apps::ecosystem::browser::engine::types::{NodeType, RenderOutput};
use alloc::collections::VecDeque;
use alloc::string::String;

pub fn render_page(html: &str, viewport_width: u32) -> RenderOutput {
    render_page_with_url(html, viewport_width, "")
}

pub fn render_page_with_url(html: &str, viewport_width: u32, base_url: &str) -> RenderOutput {
    crate::apps::ecosystem::browser::engine::image_loader::reset_image_count();
    let document = parse_html(html);
    let mut ctx = RenderContext::new(viewport_width, String::from(base_url));
    let mut node_queue: VecDeque<(&crate::apps::ecosystem::browser::engine::types::Node, bool)> =
        VecDeque::new();
    node_queue.push_back((&document.root, false));

    // Safety limit: cap the number of nodes processed to prevent runaway
    // rendering on pathological or very large DOM trees.
    const MAX_RENDER_NODES: u32 = 50_000;
    let mut nodes_processed: u32 = 0;

    while let Some((node, is_closing)) = node_queue.pop_front() {
        nodes_processed += 1;
        if nodes_processed > MAX_RENDER_NODES {
            break;
        }

        if is_closing {
            if let NodeType::Element(tag) = &node.node_type {
                handle_closing_tag(&mut ctx, tag);
            }
            continue;
        }

        match &node.node_type {
            NodeType::Text(text) => render_text(&mut ctx, text),
            NodeType::Element(tag) => {
                if should_skip_element(node, &document.hidden_classes) {
                    continue;
                }
                if is_block_element(tag) {
                    ctx.flush_line();
                }
                if let Some(style_str) = get_attribute(node, "style") {
                    apply_inline_css(&style_str, &mut ctx.current_style);
                }
                if !process_element(&mut ctx, node, tag) {
                    for child in node.children.iter().rev() {
                        node_queue.push_front((child, false));
                    }
                    node_queue.push_front((node, true));
                }
            }
            NodeType::Comment(_) => {}
        }
    }

    ctx.flush_line();

    if ctx.lines.is_empty() && !html.is_empty() {
        let fallback = crate::apps::ecosystem::browser::engine::parser::strip_tags(html);
        if !fallback.is_empty() {
            render_text(&mut ctx, &fallback);
            ctx.flush_line();
        }
    }

    RenderOutput {
        lines: ctx.lines,
        total_height: ctx.current_y,
        links: ctx.links,
        noscript_redirect: document.noscript_redirect,
    }
}

fn should_skip_element(
    node: &crate::apps::ecosystem::browser::engine::types::Node,
    hidden: &[alloc::string::String],
) -> bool {
    if node.attributes.iter().any(|(n, v)| {
        n == "style" && {
            let low = v.to_ascii_lowercase().replace(' ', "");
            low.contains("display:none") || low.contains("visibility:hidden")
        }
    }) {
        return true;
    }
    if let Some(cls) = get_attribute(node, "class") {
        if cls.split_whitespace().any(|c| hidden.iter().any(|h| h == c)) {
            return true;
        }
    }
    false
}

fn process_element(
    ctx: &mut RenderContext,
    node: &crate::apps::ecosystem::browser::engine::types::Node,
    tag: &str,
) -> bool {
    match tag {
        "a" => {
            render_link(ctx, node);
            true
        }
        "img" => {
            render_image(ctx, node);
            true
        }
        "input" => {
            render_input(ctx, node);
            true
        }
        "button" => {
            render_button(ctx, node);
            true
        }
        "select" => {
            render_select(ctx, node);
            true
        }
        "textarea" => {
            render_textarea(ctx, node);
            true
        }
        "form" => {
            ctx.form_action =
                crate::apps::ecosystem::browser::engine::parser::get_attribute(node, "action");
            ctx.form_method = Some(
                crate::apps::ecosystem::browser::engine::parser::get_attribute(node, "method")
                    .unwrap_or_else(|| alloc::string::String::from("GET")),
            );
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::ecosystem::browser::engine::RenderContent;

    #[test]
    fn test_display_none_no_space() {
        let html = r#"<div style="display:none">Hidden</div><p>Visible</p>"#;
        let output = render_page(html, 800);
        let text: String = output
            .lines
            .iter()
            .flat_map(|l| l.elements.iter())
            .filter_map(|e| {
                if let RenderContent::Text { ref text, .. } = e.content {
                    Some(text.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(!text.contains("Hidden"));
        assert!(text.contains("Visible"));
    }

    #[test]
    fn test_display_none_with_space() {
        let html = r#"<div style="display: none">Hidden</div><p>Visible</p>"#;
        let output = render_page(html, 800);
        let text: String = output
            .lines
            .iter()
            .flat_map(|l| l.elements.iter())
            .filter_map(|e| {
                if let RenderContent::Text { ref text, .. } = e.content {
                    Some(text.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(!text.contains("Hidden"));
        assert!(text.contains("Visible"));
    }

    #[test]
    fn test_display_none_extra_spaces() {
        let html = r#"<div style="display : none ;">Hidden</div><p>OK</p>"#;
        let output = render_page(html, 800);
        let text: String = output
            .lines
            .iter()
            .flat_map(|l| l.elements.iter())
            .filter_map(|e| {
                if let RenderContent::Text { ref text, .. } = e.content {
                    Some(text.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(!text.contains("Hidden"));
        assert!(text.contains("OK"));
    }

    #[test]
    fn test_noscript_redirect_in_render_output() {
        let html = r#"<html><body><noscript><meta http-equiv="refresh" content="0;url=?gbv=1"></noscript><p>Hi</p></body></html>"#;
        let output = render_page(html, 800);
        assert_eq!(output.noscript_redirect, Some(alloc::string::String::from("?gbv=1")));
    }
}
