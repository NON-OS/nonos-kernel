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
use alloc::vec::Vec;
use crate::apps::ecosystem::browser::engine::types::RenderContent;
use super::page::render_page;

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
                    if style.heading_level > 0 { line_text.push_str("## "); char_pos += 3; }
                    if style.bold { line_text.push_str("**"); char_pos += 2; }
                    if style.monospace { line_text.push('`'); char_pos += 1; }
                    line_text.push_str(text); char_pos += text.len() as u32;
                    if style.monospace { line_text.push('`'); char_pos += 1; }
                    if style.bold { line_text.push_str("**"); char_pos += 2; }
                }
                RenderContent::Link { ref text, ref href } => {
                    let start = char_pos;
                    line_text.push_str(text); char_pos += text.len() as u32;
                    if !href.is_empty() {
                        line_text.push_str(" ["); line_text.push_str(href); line_text.push(']');
                        char_pos += 3 + href.len() as u32;
                        links.push((result.len(), start * 8 + 16, char_pos * 8 + 16, href.clone()));
                    }
                }
                RenderContent::Image { ref alt, .. } => {
                    line_text.push_str("[IMG: "); line_text.push_str(if alt.is_empty() { "image" } else { alt }); line_text.push(']');
                }
                RenderContent::Input { ref name, .. } => {
                    line_text.push_str("[INPUT: "); line_text.push_str(name); line_text.push(']');
                }
                RenderContent::Button { ref text } => {
                    line_text.push_str("[BTN: "); line_text.push_str(text); line_text.push(']');
                }
                _ => {}
            }
        }
        if !line_text.trim().is_empty() { result.push(line_text); }
    }

    if result.is_empty() {
        for line in html.lines() {
            let t = line.trim();
            if !t.is_empty() { result.push(String::from(t)); }
        }
    }
    (result, links)
}
