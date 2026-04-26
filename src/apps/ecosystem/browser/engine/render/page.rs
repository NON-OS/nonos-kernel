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
use crate::apps::ecosystem::browser::engine::types::{NodeType, RenderOutput};
use crate::apps::ecosystem::browser::engine::types::TextAlign;
use crate::apps::ecosystem::browser::engine::parser::{parse_html, get_attribute};
use super::context::RenderContext;
use super::block::is_block_element;
use super::text::render_text;
use super::closing::handle_closing_tag;
use super::css::apply_inline_css;
use super::elements::{render_link, render_image, render_input, render_button, render_select, render_textarea};

const MAX_RENDER_HTML_BYTES: usize = 96 * 1024;
const MAX_RENDER_MS: u64 = 250;

pub fn render_page(html: &str, viewport_width: u32) -> RenderOutput {
    render_page_with_url(html, viewport_width, "")
}

pub fn render_page_with_url(html: &str, viewport_width: u32, base_url: &str) -> RenderOutput {
    crate::apps::ecosystem::browser::engine::image_loader::reset_image_count();
    let render_start = crate::time::timestamp_millis();
    let render_html = bounded_html(html);
    let document = parse_html(render_html);
    let mut ctx = RenderContext::new(viewport_width, String::from(base_url));
    let mut node_queue: VecDeque<(&crate::apps::ecosystem::browser::engine::types::Node, bool)> = VecDeque::new();
    node_queue.push_back((&document.root, false));

    // Safety limit: cap the number of nodes processed to prevent runaway
    // rendering on pathological or very large DOM trees.
    const MAX_RENDER_NODES: u32 = 50_000;
    let mut nodes_processed: u32 = 0;

    while let Some((node, is_closing)) = node_queue.pop_front() {
        nodes_processed += 1;
        if nodes_processed > MAX_RENDER_NODES { break; }
        if ctx.is_full() { break; }
        if nodes_processed & 0xff == 0 && elapsed_ms_since(render_start) > MAX_RENDER_MS { break; }

        if is_closing {
            if let NodeType::Element(tag) = &node.node_type {
                handle_closing_tag(&mut ctx, tag);
            }
            continue;
        }

        match &node.node_type {
            NodeType::Text(text) => render_text(&mut ctx, text),
            NodeType::Element(tag) => {
                if should_skip_element(node, &document.hidden_classes) { continue; }
                if is_block_element(tag) { ctx.flush_line(); }
                if !is_leaf_element(tag) { apply_element_style(&mut ctx, node, tag, &document.centered_classes); }
                if !process_element(&mut ctx, node, tag) {
                    for child in node.children.iter().rev() { node_queue.push_front((child, false)); }
                    node_queue.push_front((node, true));
                }
            }
            NodeType::Comment(_) => {}
        }
    }

    ctx.flush_line();

    if ctx.lines.is_empty() && !render_html.is_empty() {
        let fallback = crate::apps::ecosystem::browser::engine::parser::strip_tags(render_html);
        if !fallback.is_empty() { render_text(&mut ctx, &fallback); ctx.flush_line(); }
    }

    RenderOutput { lines: ctx.lines, total_height: ctx.current_y, links: ctx.links, noscript_redirect: document.noscript_redirect }
}

fn elapsed_ms_since(start: u64) -> u64 { crate::time::timestamp_millis().saturating_sub(start) }

fn bounded_html(html: &str) -> &str {
    if html.len() <= MAX_RENDER_HTML_BYTES { return html; }
    let mut end = MAX_RENDER_HTML_BYTES;
    while end > 0 && !html.is_char_boundary(end) { end -= 1; }
    &html[..end]
}

fn should_skip_element(node: &crate::apps::ecosystem::browser::engine::types::Node, hidden: &[alloc::string::String]) -> bool {
    if node.attributes.iter().any(|(n, v)| n == "style" && {
        let low = v.to_ascii_lowercase().replace(' ', "");
        low.contains("display:none") || low.contains("visibility:hidden")
    }) { return true; }
    if let Some(cls) = get_attribute(node, "class") {
        if cls.split_whitespace().any(|c| hidden.iter().any(|h| h == c)) { return true; }
    }
    false
}

fn is_leaf_element(tag: &str) -> bool {
    matches!(tag, "a" | "img" | "input" | "button" | "select" | "textarea")
}

fn apply_element_style(ctx: &mut RenderContext, node: &crate::apps::ecosystem::browser::engine::types::Node, tag: &str, centered_classes: &[String]) {
    ctx.style_stack.push(ctx.current_style);
    match tag {
        "b" | "strong" | "th" => ctx.current_style.bold = true,
        "i" | "em" => ctx.current_style.italic = true,
        "u" => ctx.current_style.underline = true,
        "code" | "pre" => ctx.current_style.monospace = true,
        "center" => ctx.current_style.text_align = TextAlign::Center,
        "h1" => { ctx.current_style.bold = true; ctx.current_style.heading_level = 1; ctx.current_style.text_align = TextAlign::Center; }
        "h2" => { ctx.current_style.bold = true; ctx.current_style.heading_level = 2; }
        "h3" => { ctx.current_style.bold = true; ctx.current_style.heading_level = 3; }
        _ => {}
    }
    if let Some(align) = get_attribute(node, "align") {
        match align.to_ascii_lowercase().as_str() {
            "center" => ctx.current_style.text_align = TextAlign::Center,
            "right" => ctx.current_style.text_align = TextAlign::Right,
            _ => {}
        }
    }
    if class_matches(node, centered_classes) {
        ctx.current_style.text_align = TextAlign::Center;
    }
    if let Some(style_str) = get_attribute(node, "style") {
        apply_inline_css(&style_str, &mut ctx.current_style);
    }
}

fn class_matches(node: &crate::apps::ecosystem::browser::engine::types::Node, classes: &[String]) -> bool {
    get_attribute(node, "class")
        .map(|class_attr| class_attr.split_whitespace().any(|class_name| classes.iter().any(|known| known == class_name)))
        .unwrap_or(false)
}

fn process_element(ctx: &mut RenderContext, node: &crate::apps::ecosystem::browser::engine::types::Node, tag: &str) -> bool {
    match tag {
        "a" => { render_link(ctx, node); true }
        "img" => { render_image(ctx, node); true }
        "input" => { render_input(ctx, node); true }
        "button" => { render_button(ctx, node); true }
        "select" => { render_select(ctx, node); true }
        "textarea" => { render_textarea(ctx, node); true }
        "form" => {
            ctx.form_action = crate::apps::ecosystem::browser::engine::parser::get_attribute(node, "action");
            ctx.form_method = Some(crate::apps::ecosystem::browser::engine::parser::get_attribute(node, "method")
                .unwrap_or_else(|| alloc::string::String::from("GET")));
            false
        }
        _ => false
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
        let text: String = output.lines.iter().flat_map(|l| l.elements.iter()).filter_map(|e| {
            if let RenderContent::Text { ref text, .. } = e.content { Some(text.as_str()) } else { None }
        }).collect();
        assert!(!text.contains("Hidden"));
        assert!(text.contains("Visible"));
    }

    #[test]
    fn test_display_none_with_space() {
        let html = r#"<div style="display: none">Hidden</div><p>Visible</p>"#;
        let output = render_page(html, 800);
        let text: String = output.lines.iter().flat_map(|l| l.elements.iter()).filter_map(|e| {
            if let RenderContent::Text { ref text, .. } = e.content { Some(text.as_str()) } else { None }
        }).collect();
        assert!(!text.contains("Hidden"));
        assert!(text.contains("Visible"));
    }

    #[test]
    fn test_display_none_extra_spaces() {
        let html = r#"<div style="display : none ;">Hidden</div><p>OK</p>"#;
        let output = render_page(html, 800);
        let text: String = output.lines.iter().flat_map(|l| l.elements.iter()).filter_map(|e| {
            if let RenderContent::Text { ref text, .. } = e.content { Some(text.as_str()) } else { None }
        }).collect();
        assert!(!text.contains("Hidden"));
        assert!(text.contains("OK"));
    }

    #[test]
    fn test_noscript_redirect_in_render_output() {
        let html = r#"<html><body><noscript><meta http-equiv="refresh" content="0;url=?gbv=1"></noscript><p>Hi</p></body></html>"#;
        let output = render_page(html, 800);
        assert_eq!(output.noscript_redirect, Some(alloc::string::String::from("?gbv=1")));
    }

    #[test]
    fn test_stylesheet_center_class_aligns_text() {
        let html = r#"<style>.hero{text-align:center}</style><div class="hero">Centered</div>"#;
        let output = render_page(html, 800);
        let first_x = output.lines[0].elements[0].x;
        assert!(first_x > 300);
    }

    #[test]
    fn test_centered_textarea_honors_alignment() {
        let html = r#"<style>.form{text-align:center}</style><div class="form"><textarea cols="20"></textarea></div>"#;
        let output = render_page(html, 800);
        let (x, width) = output.lines.iter().flat_map(|line| line.elements.iter()).find_map(|elem| match elem.content {
            RenderContent::Textarea { .. } => Some((elem.x, elem.width)),
            _ => None,
        }).unwrap();
        assert_centered(x, width, 800);
    }

    #[test]
    fn test_google_like_fixture_centers_core_regions() {
        for viewport_width in [800, 1200] {
            let output = render_page(google_like_fixture(), viewport_width);
            let (logo_x, logo_width) = first_image_bounds(&output).unwrap();
            let (input_x, input_width) = first_input_bounds(&output).unwrap();
            let button_x = first_button_x(&output).unwrap();
            let link_x = first_link_x(&output).unwrap();
            assert_centered(logo_x, logo_width, viewport_width);
            assert_centered(input_x, input_width, viewport_width);
            assert!(button_x > viewport_width / 3);
            assert!(link_x > viewport_width / 3);
        }
    }

    fn google_like_fixture() -> &'static str {
        r#"<style>
        .logo{text-align:center}.search{text-align:center}.links{text-align:center}
        </style><main>
        <div class="logo"><img src="/logo.png" width="272" height="92" alt="Google"></div>
        <form class="search"><input name="q" type="search"><button>Search</button><button>Lucky</button></form>
        <div class="links"><a href="/about">About</a><a href="/store">Store</a></div>
        </main>"#
    }

    fn first_image_bounds(output: &crate::apps::ecosystem::browser::engine::types::RenderOutput) -> Option<(u32, u32)> {
        output.lines.iter().flat_map(|line| line.elements.iter()).find_map(|elem| match elem.content {
            RenderContent::Image { .. } | RenderContent::DecodedImage { .. } => Some((elem.x, elem.width)),
            _ => None,
        })
    }

    fn first_input_bounds(output: &crate::apps::ecosystem::browser::engine::types::RenderOutput) -> Option<(u32, u32)> {
        output.lines.iter().flat_map(|line| line.elements.iter()).find_map(|elem| match elem.content {
            RenderContent::Input { .. } => Some((elem.x, elem.width)),
            _ => None,
        })
    }

    fn first_button_x(output: &crate::apps::ecosystem::browser::engine::types::RenderOutput) -> Option<u32> {
        output.lines.iter().flat_map(|line| line.elements.iter()).find_map(|elem| match elem.content {
            RenderContent::Button { .. } => Some(elem.x),
            _ => None,
        })
    }

    fn first_link_x(output: &crate::apps::ecosystem::browser::engine::types::RenderOutput) -> Option<u32> {
        output.lines.iter().flat_map(|line| line.elements.iter()).find_map(|elem| match elem.content {
            RenderContent::Link { .. } => Some(elem.x),
            _ => None,
        })
    }

    fn assert_centered(x: u32, width: u32, viewport_width: u32) {
        let center = x + width / 2;
        let expected = viewport_width / 2;
        assert!(center.abs_diff(expected) <= 8);
    }
}
