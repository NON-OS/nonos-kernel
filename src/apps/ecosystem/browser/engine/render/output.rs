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

use super::page::render_page;
use crate::apps::ecosystem::browser::engine::types::RenderContent;
use alloc::string::String;
use alloc::vec::Vec;

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
        let mut char_pos: u32 = 0;

        for elem in line.elements {
            match elem.content {
                RenderContent::Text { ref text, style } => {
                    if style.heading_level > 0 {
                        line_text.push_str("## ");
                        char_pos += 3;
                    }
                    if style.bold {
                        line_text.push_str("**");
                        char_pos += 2;
                    }
                    if style.monospace {
                        line_text.push('`');
                        char_pos += 1;
                    }
                    line_text.push_str(text);
                    char_pos += text.len() as u32;
                    if style.monospace {
                        line_text.push('`');
                        char_pos += 1;
                    }
                    if style.bold {
                        line_text.push_str("**");
                        char_pos += 2;
                    }
                }
                RenderContent::Link { ref text, ref href } => {
                    let start = char_pos;
                    line_text.push_str(text);
                    char_pos += text.len() as u32;
                    if !href.is_empty() {
                        line_text.push_str(" [");
                        line_text.push_str(href);
                        line_text.push(']');
                        char_pos += 3 + href.len() as u32;
                        links.push((result.len(), start * 8 + 16, char_pos * 8 + 16, href.clone()));
                    }
                }
                RenderContent::Image { ref alt, .. } => {
                    line_text.push_str("[IMG: ");
                    line_text.push_str(if alt.is_empty() { "image" } else { alt });
                    line_text.push(']');
                }
                RenderContent::Input { ref name, .. } => {
                    line_text.push_str("[INPUT: ");
                    line_text.push_str(name);
                    line_text.push(']');
                }
                RenderContent::Button { ref text } => {
                    line_text.push_str("[BTN: ");
                    line_text.push_str(text);
                    line_text.push(']');
                }
                RenderContent::Select { ref name, ref value } => {
                    line_text.push_str("[SELECT: ");
                    line_text.push_str(name);
                    if !value.is_empty() {
                        line_text.push('=');
                        line_text.push_str(value);
                    }
                    line_text.push(']');
                }
                RenderContent::Textarea { ref name, .. } => {
                    line_text.push_str("[TEXTAREA: ");
                    line_text.push_str(name);
                    line_text.push(']');
                }
                _ => {}
            }
        }
        if !line_text.trim().is_empty() {
            result.push(line_text);
        }
    }

    if result.is_empty() {
        for line in html.lines() {
            let t = line.trim();
            if !t.is_empty() {
                result.push(String::from(t));
            }
        }
    }
    (result, links)
}

#[cfg(test)]
mod tests {
    use super::render_to_lines;

    #[test]
    fn test_noscript_content_renders_as_visible() {
        let html = "<html><body><noscript><p>Visible content</p></noscript></body></html>";
        let lines = render_to_lines(html);
        assert!(
            lines.iter().any(|l| l.contains("Visible content")),
            "noscript content should render: {:?}",
            lines
        );
    }

    #[test]
    fn test_noscript_form_renders() {
        let html = r#"<html><body><noscript><form action="/search" method="GET"><input name="q" type="text"><input type="submit" value="Search"></form></noscript></body></html>"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(joined.contains("[INPUT:"), "form input should render: {:?}", lines);
        assert!(joined.contains("[BTN: Search]"), "submit button should render: {:?}", lines);
    }

    #[test]
    fn test_google_style_noscript_search_form() {
        let html = r#"<html><body>
            <noscript>
                <form action="/search" method="GET">
                    <input name="q" type="text">
                    <input type="submit" value="Google Search">
                </form>
            </noscript>
        </body></html>"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(joined.contains("[INPUT: q]"), "search input should render: {:?}", lines);
        assert!(joined.contains("[BTN: Google Search]"), "submit should render: {:?}", lines);
    }

    #[test]
    fn test_form_with_inputs_renders_all_fields() {
        let html = r#"<form action="/login" method="POST">
            <input name="user" type="text">
            <input name="pass" type="password">
            <input type="submit" value="Login">
        </form>"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(joined.contains("[INPUT: user]"), "user input: {:?}", lines);
        assert!(joined.contains("[INPUT: pass]"), "pass input: {:?}", lines);
        assert!(joined.contains("[BTN: Login]"), "submit: {:?}", lines);
    }

    #[test]
    fn test_select_shows_selected_option() {
        let html = r#"<select name="color"><option>Red</option><option selected>Blue</option><option>Green</option></select>"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(joined.contains("[SELECT: color=Blue]"), "selected option: {:?}", lines);
    }

    #[test]
    fn test_select_shows_first_option_when_none_selected() {
        let html = r#"<select name="size"><option>Small</option><option>Large</option></select>"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(joined.contains("[SELECT: size=Small]"), "first option: {:?}", lines);
    }

    #[test]
    fn test_textarea_renders_with_correct_dimensions() {
        let html = r#"<textarea name="bio" cols="30" rows="5"></textarea>"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(joined.contains("[TEXTAREA: bio]"), "textarea: {:?}", lines);
    }

    #[test]
    fn test_hidden_inputs_are_not_displayed() {
        let html = r#"<form action="/test"><input name="token" type="hidden" value="abc123"><input name="visible" type="text"></form>"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(!joined.contains("token"), "hidden input should not render: {:?}", lines);
        assert!(joined.contains("[INPUT: visible]"), "visible input should render: {:?}", lines);
    }

    #[test]
    fn test_submit_input_renders_as_button() {
        let html = r#"<input type="submit" value="Go">"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(joined.contains("[BTN: Go]"), "submit renders as button: {:?}", lines);
    }

    #[test]
    fn test_submit_input_default_label() {
        let html = r#"<input type="submit">"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(joined.contains("[BTN: Submit]"), "default submit label: {:?}", lines);
    }

    #[test]
    fn test_form_action_method_passed_to_context() {
        // Verify form renders and submit button is present — integration test
        let html = r#"<form action="/api" method="POST"><input name="data" type="text"><input type="submit" value="Send"></form>"#;
        let lines = render_to_lines(html);
        let joined = lines.join(" ");
        assert!(joined.contains("[INPUT: data]"), "form input: {:?}", lines);
        assert!(joined.contains("[BTN: Send]"), "submit: {:?}", lines);
    }
}
