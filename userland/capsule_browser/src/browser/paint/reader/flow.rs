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

use alloc::vec::Vec;

use nonos_toolkit::font::ttf::line_height;

use super::face;
use super::style::{advance, bold, px, Style};
use crate::browser::reader::extract::{Article, Para};
use crate::browser::shell::kept::ReaderPrefs;
use crate::browser::ui::wrap::wrap;

const SIZES: [f32; 5] = [18.0, 19.0, 20.0, 22.0, 24.0];
const TOP: i32 = 48;
const BOTTOM: i32 = 80;
pub const QUOTE_IN: i32 = 20;

pub struct Line<'a> {
    pub y: i32,
    pub text: &'a str,
    pub style: Style,
}

/// An article set into a column: where the site label and reading time go,
/// every wrapped line, and the height of the whole.
pub struct Flow<'a> {
    pub body: f32,
    pub site_y: i32,
    pub time_y: Option<i32>,
    pub lines: Vec<Line<'a>>,
    pub height: i32,
}

/// `a` set into a column `col_w` wide at the size `prefs` asks for.
pub fn flow<'a>(a: &'a Article, prefs: &ReaderPrefs, col_w: i32) -> Flow<'a> {
    let body = SIZES[(prefs.size as usize).min(4)];
    let gap = body as i32;
    let mut f = Flow { body, site_y: TOP, time_y: None, lines: Vec::new(), height: 0 };
    let mut y = TOP + line_height(body) + gap / 2;
    y = push(&mut f.lines, &a.title, Style::Title, body, col_w, y);
    if prefs.show_time {
        f.time_y = Some(y + gap / 4);
        y += line_height(body) + gap / 4;
    }
    y += 2 * gap;
    for p in &a.paras {
        let style = match p {
            Para::Heading(_) => Style::Heading,
            Para::Text(_) => Style::Body,
            Para::Quote(_) => Style::Quote,
        };
        y += if style == Style::Heading { gap / 2 } else { 0 };
        y = push(&mut f.lines, p.text(), style, body, col_w, y) + gap;
    }
    f.height = y + BOTTOM;
    f
}

fn push<'a>(
    out: &mut Vec<Line<'a>>,
    text: &'a str,
    style: Style,
    body: f32,
    col_w: i32,
    y: i32,
) -> i32 {
    let (size, b) = (px(style, body), bold(style));
    let w = if style == Style::Quote { col_w - QUOTE_IN } else { col_w };
    let mut y = y;
    for (s, e) in wrap(text, w, |t| face::measure(t, size, b)) {
        out.push(Line { y, text: &text[s..e], style });
        y += advance(style, body);
    }
    y
}
