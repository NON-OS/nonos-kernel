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

use crate::graphics::framebuffer::{COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};

use super::state::{PAGE_TITLE, PAGE_TITLE_LEN, clear_links};
use super::constants::MAX_CONTENT_LINES;
use super::html_entities::try_parse_entity;
use super::html_tags::process_tag;

pub(super) fn parse_html(html: &[u8]) -> Vec<(String, u32)> {
    clear_links();

    let mut lines: Vec<(String, u32)> = Vec::new();
    let mut current_line = String::new();
    let mut in_tag = false;
    let mut tag_name = String::new();
    let mut skip_content = false;
    let mut is_heading = false;
    let mut in_pre = false;
    let mut title_buf = String::new();
    let mut in_title = false;
    let mut in_link = false;
    let mut link_href = String::new();
    let mut link_start_char = 0usize;

    let color_normal = COLOR_TEXT_WHITE;
    let color_heading = COLOR_ACCENT;
    let color_link = COLOR_GREEN;

    let mut i = 0;
    while i < html.len() {
        let ch = html[i] as char;

        if ch == '<' {
            in_tag = true;
            tag_name.clear();
            i += 1;
            continue;
        }

        if in_tag {
            if ch == '>' {
                in_tag = false;
                let tag_lower = tag_name.to_lowercase();
                process_tag(&tag_lower, &tag_name, &mut lines, &mut current_line, &mut is_heading,
                           &mut skip_content, &mut in_pre, &mut in_title, &mut title_buf,
                           &mut in_link, &mut link_href, &mut link_start_char,
                           color_normal, color_heading, color_link);
            } else {
                tag_name.push(ch);
            }
            i += 1;
            continue;
        }

        if skip_content {
            i += 1;
            continue;
        }

        if in_title {
            if ch != '\n' && ch != '\r' {
                title_buf.push(ch);
            }
            i += 1;
            continue;
        }

        if ch == '&' && i + 1 < html.len() {
            let remaining = &html[i..];
            if let Some(advance) = try_parse_entity(remaining, &mut current_line) {
                i += advance;
                continue;
            }
        }

        if ch == '\n' || ch == '\r' {
            if in_pre {
                let color = if is_heading { color_heading } else { color_normal };
                lines.push((core::mem::take(&mut current_line), color));
            } else if !current_line.is_empty() && !current_line.ends_with(' ') {
                current_line.push(' ');
            }
        } else if ch == ' ' || ch == '\t' {
            if in_pre {
                current_line.push(ch);
            } else if !current_line.is_empty() && !current_line.ends_with(' ') {
                current_line.push(' ');
            }
        } else {
            current_line.push(ch);
        }

        if current_line.len() > 80 {
            let color = if is_heading { color_heading } else { color_normal };
            if let Some(space_pos) = current_line.rfind(' ') {
                let rest = String::from(&current_line[space_pos + 1..]);
                current_line.truncate(space_pos);
                lines.push((core::mem::take(&mut current_line), color));
                current_line = rest;
            } else {
                lines.push((core::mem::take(&mut current_line), color));
            }
        }

        i += 1;
    }

    if !current_line.is_empty() {
        let color = if is_heading { color_heading } else { color_normal };
        lines.push((current_line, color));
    }

    if PAGE_TITLE_LEN.load(Ordering::Relaxed) == 0 {
        let mut title = PAGE_TITLE.lock();
        let default = b"Untitled Page";
        title[..default.len()].copy_from_slice(default);
        PAGE_TITLE_LEN.store(default.len(), Ordering::Relaxed);
    }

    if lines.len() > MAX_CONTENT_LINES {
        lines.truncate(MAX_CONTENT_LINES);
    }

    lines
}
