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

use super::helpers::parse_dimension;
use super::shapes::{draw_svg_circle, draw_svg_line, draw_svg_polyline, draw_svg_rect};
use crate::apps::ecosystem::browser::engine::parser::get_attribute;
use crate::apps::ecosystem::browser::engine::types::{ImageData, Node, NodeType};

pub fn render_svg(node: &Node, default_width: u32, default_height: u32) -> Option<ImageData> {
    match &node.node_type {
        NodeType::Element(t) if t == "svg" => {}
        _ => return None,
    }
    let width =
        get_attribute(node, "width").and_then(|v| parse_dimension(&v)).unwrap_or(default_width);
    let height =
        get_attribute(node, "height").and_then(|v| parse_dimension(&v)).unwrap_or(default_height);
    if width == 0 || height == 0 || width > 4096 || height > 4096 {
        return None;
    }
    let mut pixels = alloc::vec![0x00000000u32; (width as usize) * (height as usize)];
    for child in &node.children {
        if let NodeType::Element(child_tag) = &child.node_type {
            match child_tag.as_str() {
                "rect" => draw_svg_rect(child, &mut pixels, width, height),
                "circle" => draw_svg_circle(child, &mut pixels, width, height),
                "line" => draw_svg_line(child, &mut pixels, width, height),
                "polyline" => draw_svg_polyline(child, &mut pixels, width, height),
                _ => {}
            }
        }
    }
    Some(ImageData { width, height, pixels })
}
