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

use crate::apps::ecosystem::browser::engine::svg::parse_css_color;
use crate::apps::ecosystem::browser::engine::types::{TextAlign, TextStyle};

pub(super) fn apply_inline_css(style_str: &str, style: &mut TextStyle) {
    for part in style_str.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((prop, val)) = part.split_once(':') {
            let prop = prop.trim().to_ascii_lowercase();
            let val = val.trim();
            match prop.as_str() {
                "color" => {
                    if let Some(c) = parse_css_color(val) {
                        style.color = Some(c);
                    }
                }
                "background-color" | "background" => {
                    if let Some(c) = parse_css_color(val) {
                        style.bg_color = Some(c);
                    }
                }
                "font-size" => {
                    let num_str = val.trim_end_matches("px").trim_end_matches("pt").trim();
                    if let Ok(n) = num_str.parse::<u8>() {
                        style.font_scale = n;
                    }
                }
                "text-align" => {
                    let v = val.to_ascii_lowercase();
                    style.text_align = match v.as_str() {
                        "center" => TextAlign::Center,
                        "right" => TextAlign::Right,
                        _ => TextAlign::Left,
                    };
                }
                _ => {}
            }
        }
    }
}
