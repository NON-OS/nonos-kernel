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
use core::sync::atomic::Ordering;

use crate::graphics::framebuffer::COLOR_TEXT_DIM;

use super::state::{PAGE_TITLE, PAGE_TITLE_LEN, add_link};

pub(super) fn process_tag(
    tag_lower: &str,
    tag_name: &str,
    lines: &mut Vec<(String, u32)>,
    current_line: &mut String,
    is_heading: &mut bool,
    skip_content: &mut bool,
    in_pre: &mut bool,
    in_title: &mut bool,
    title_buf: &mut String,
    in_link: &mut bool,
    link_href: &mut String,
    link_start_char: &mut usize,
    color_normal: u32,
    color_heading: u32,
    color_link: u32,
) {
    static mut IN_TABLE: bool = false;
    static mut IN_OL: bool = false;
    static mut OL_COUNTER: usize = 0;

    match tag_lower {
        "br" | "br/" => {
            let color = if *is_heading { color_heading } else { color_normal };
            if !current_line.is_empty() || lines.is_empty() {
                lines.push((core::mem::take(current_line), color));
            }
        }
        "p" | "div" | "article" | "section" | "header" | "footer" | "main" | "aside" => {
            let color = if *is_heading { color_heading } else { color_normal };
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color));
            }
        }
        "blockquote" => {
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color_normal));
            }
            current_line.push_str("  | ");
        }
        "/blockquote" => {
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), COLOR_TEXT_DIM));
            }
            lines.push((String::new(), color_normal));
        }
        "ul" => {
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color_normal));
            }
        }
        "ol" => {
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color_normal));
            }
            unsafe { IN_OL = true; OL_COUNTER = 0; }
        }
        "/ol" => {
            unsafe { IN_OL = false; OL_COUNTER = 0; }
        }
        "li" => {
            let color = if *is_heading { color_heading } else { color_normal };
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color));
            }
            if unsafe { IN_OL } {
                unsafe { OL_COUNTER += 1; }
                let num = alloc::format!("  {}. ", unsafe { OL_COUNTER });
                current_line.push_str(&num);
            } else {
                current_line.push_str("  * ");
            }
        }
        "/p" | "/div" | "/li" | "/article" | "/section" | "/header" | "/footer" | "/main" | "/aside" => {
            let color = if *is_heading { color_heading } else { color_normal };
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color));
            }
            lines.push((String::new(), color_normal));
        }
        t if t.starts_with("h1") || t.starts_with("h2") || t.starts_with("h3")
          || t.starts_with("h4") || t.starts_with("h5") || t.starts_with("h6") => {
            *is_heading = true;
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color_normal));
            }
        }
        "/h1" | "/h2" | "/h3" | "/h4" | "/h5" | "/h6" => {
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color_heading));
            }
            lines.push((String::new(), color_normal));
            *is_heading = false;
        }
        "table" => {
            unsafe { IN_TABLE = true; }
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color_normal));
            }
        }
        "/table" => {
            unsafe { IN_TABLE = false; }
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color_normal));
            }
            lines.push((String::new(), color_normal));
        }
        "tr" | "/tr" => {
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color_normal));
            }
        }
        "td" | "th" => {
            if !current_line.is_empty() && !current_line.ends_with(' ') {
                current_line.push_str(" | ");
            }
        }
        "/td" | "/th" => {}
        t if t.starts_with("img ") || t == "img" => {
            if let Some(alt_start) = tag_name.find("alt=") {
                let rest = &tag_name[alt_start + 4..];
                let quote = if rest.starts_with('"') { '"' } else if rest.starts_with('\'') { '\'' } else { ' ' };
                if quote != ' ' {
                    if let Some(end) = rest[1..].find(quote) {
                        current_line.push_str("[IMG: ");
                        current_line.push_str(&rest[1..end + 1]);
                        current_line.push(']');
                    }
                }
            } else {
                current_line.push_str("[IMG]");
            }
        }
        "strong" | "b" => current_line.push_str("**"),
        "/strong" | "/b" => current_line.push_str("**"),
        "em" | "i" => current_line.push('_'),
        "/em" | "/i" => current_line.push('_'),
        t if t.starts_with("a ") || t == "a" => {
            link_href.clear();
            if let Some(href_start) = tag_name.find("href=") {
                let rest = &tag_name[href_start + 5..];
                let quote = if rest.starts_with('"') { '"' } else if rest.starts_with('\'') { '\'' } else { ' ' };
                if quote != ' ' {
                    if let Some(end) = rest[1..].find(quote) {
                        *link_href = String::from(&rest[1..end + 1]);
                    }
                } else {
                    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                    *link_href = String::from(&rest[..end]);
                }
            }
            *in_link = true;
            *link_start_char = current_line.len();
            current_line.push('[');
        }
        "/a" => {
            current_line.push(']');
            if *in_link && !link_href.is_empty() {
                let line_idx = lines.len();
                let end_char = current_line.len();
                add_link(line_idx, *link_start_char, end_char, link_href.clone());
                lines.push((core::mem::take(current_line), color_link));
            }
            *in_link = false;
            link_href.clear();
        }
        "pre" | "code" => *in_pre = true,
        "/pre" | "/code" => *in_pre = false,
        "title" => {
            *in_title = true;
            title_buf.clear();
        }
        "/title" => {
            *in_title = false;
            let mut title = PAGE_TITLE.lock();
            let len = title_buf.len().min(63);
            title[..len].copy_from_slice(&title_buf.as_bytes()[..len]);
            PAGE_TITLE_LEN.store(len, Ordering::Relaxed);
        }
        "script" | "style" => *skip_content = true,
        "/script" | "/style" => *skip_content = false,
        "hr" => {
            if !current_line.is_empty() {
                lines.push((core::mem::take(current_line), color_normal));
            }
            lines.push((String::from("----------------------------------------"), color_normal));
        }
        _ => {}
    }
}
