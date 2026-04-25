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

pub(super) fn parse_svg_color(s: &str) -> Option<u32> {
    let s = s.trim();
    if s.is_empty() || s == "none" {
        return None;
    }
    parse_css_color(s)
}

pub(crate) fn parse_css_color(s: &str) -> Option<u32> {
    let s = s.trim();
    if s.starts_with('#') {
        let hex = &s[1..];
        if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()? as u32;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()? as u32;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()? as u32;
            return Some(0xFF000000 | (r << 16) | (g << 8) | b);
        } else if hex.len() == 3 {
            let r = u8::from_str_radix(&hex[0..1], 16).ok()? as u32;
            let g = u8::from_str_radix(&hex[1..2], 16).ok()? as u32;
            let b = u8::from_str_radix(&hex[2..3], 16).ok()? as u32;
            return Some(0xFF000000 | (r * 17) << 16 | (g * 17) << 8 | (b * 17));
        }
        return None;
    }
    match s.to_ascii_lowercase().as_str() {
        "black" => Some(0xFF000000),
        "white" => Some(0xFFFFFFFF),
        "red" => Some(0xFFFF0000),
        "green" => Some(0xFF008000),
        "blue" => Some(0xFF0000FF),
        "yellow" => Some(0xFFFFFF00),
        "cyan" | "aqua" => Some(0xFF00FFFF),
        "magenta" | "fuchsia" => Some(0xFFFF00FF),
        "orange" => Some(0xFFFFA500),
        "purple" => Some(0xFF800080),
        "gray" | "grey" => Some(0xFF808080),
        "silver" => Some(0xFFC0C0C0),
        "navy" => Some(0xFF000080),
        "teal" => Some(0xFF008080),
        "maroon" => Some(0xFF800000),
        "olive" => Some(0xFF808000),
        "lime" => Some(0xFF00FF00),
        "transparent" => Some(0x00000000),
        _ => None,
    }
}
