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

use super::color::parse_svg_color;
use super::helpers::{attr_i32, attr_u32, parse_points};
use super::line::bresenham_line;
use crate::apps::ecosystem::browser::engine::parser::get_attribute;
use crate::apps::ecosystem::browser::engine::types::Node;

pub(super) fn draw_svg_rect(node: &Node, pixels: &mut [u32], canvas_w: u32, canvas_h: u32) {
    let (x, y) = (attr_u32(node, "x").unwrap_or(0), attr_u32(node, "y").unwrap_or(0));
    let (w, h) = (attr_u32(node, "width").unwrap_or(0), attr_u32(node, "height").unwrap_or(0));
    let fill =
        parse_svg_color(&get_attribute(node, "fill").unwrap_or_default()).unwrap_or(0xFF000000);
    let (x1, y1, x2, y2) =
        (x.min(canvas_w), y.min(canvas_h), (x + w).min(canvas_w), (y + h).min(canvas_h));
    for py in y1..y2 {
        for px in x1..x2 {
            pixels[(py * canvas_w + px) as usize] = fill;
        }
    }
    if let Some(stroke) = get_attribute(node, "stroke") {
        if let Some(color) = parse_svg_color(&stroke) {
            for px in x1..x2 {
                if y1 < canvas_h {
                    pixels[(y1 * canvas_w + px) as usize] = color;
                }
                if y2 > 0 && y2 - 1 < canvas_h {
                    pixels[((y2 - 1) * canvas_w + px) as usize] = color;
                }
            }
            for py in y1..y2 {
                if x1 < canvas_w {
                    pixels[(py * canvas_w + x1) as usize] = color;
                }
                if x2 > 0 && x2 - 1 < canvas_w {
                    pixels[(py * canvas_w + x2 - 1) as usize] = color;
                }
            }
        }
    }
}

pub(super) fn draw_svg_circle(node: &Node, pixels: &mut [u32], canvas_w: u32, canvas_h: u32) {
    let (cx, cy, r) = (
        attr_i32(node, "cx").unwrap_or(0),
        attr_i32(node, "cy").unwrap_or(0),
        attr_i32(node, "r").unwrap_or(0),
    );
    let fill =
        parse_svg_color(&get_attribute(node, "fill").unwrap_or_default()).unwrap_or(0xFF000000);
    if r <= 0 {
        return;
    }
    let (y0, y1) = ((cy - r).max(0) as u32, ((cy + r) as u32).min(canvas_h));
    let (x0, x1) = ((cx - r).max(0) as u32, ((cx + r) as u32).min(canvas_w));
    let r_sq = (r * r) as i64;
    for py in y0..y1 {
        for px in x0..x1 {
            let (dx, dy) = (px as i32 - cx, py as i32 - cy);
            if (dx as i64 * dx as i64 + dy as i64 * dy as i64) <= r_sq {
                pixels[(py * canvas_w + px) as usize] = fill;
            }
        }
    }
}

pub(super) fn draw_svg_line(node: &Node, pixels: &mut [u32], canvas_w: u32, canvas_h: u32) {
    let (x1, y1, x2, y2) = (
        attr_i32(node, "x1").unwrap_or(0),
        attr_i32(node, "y1").unwrap_or(0),
        attr_i32(node, "x2").unwrap_or(0),
        attr_i32(node, "y2").unwrap_or(0),
    );
    let color =
        parse_svg_color(&get_attribute(node, "stroke").unwrap_or_default()).unwrap_or(0xFF000000);
    bresenham_line(x1, y1, x2, y2, color, pixels, canvas_w, canvas_h);
}

pub(super) fn draw_svg_polyline(node: &Node, pixels: &mut [u32], canvas_w: u32, canvas_h: u32) {
    let points_str = match get_attribute(node, "points") {
        Some(s) => s,
        None => return,
    };
    let color =
        parse_svg_color(&get_attribute(node, "stroke").unwrap_or_default()).unwrap_or(0xFF000000);
    let coords = parse_points(&points_str);
    for i in 1..coords.len() {
        bresenham_line(
            coords[i - 1].0,
            coords[i - 1].1,
            coords[i].0,
            coords[i].1,
            color,
            pixels,
            canvas_w,
            canvas_h,
        );
    }
}
