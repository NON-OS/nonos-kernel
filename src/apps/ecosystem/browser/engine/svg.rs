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

//! Minimal SVG subset renderer for the NONOS browser engine.
//!
//! Supports: `<rect>`, `<circle>`, `<line>`, `<polyline>`
//! Rasterizes SVG primitives into an `ImageData` pixel buffer.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use super::types::{ImageData, Node, NodeType};
use super::parser::get_attribute;

/// Rasterize an `<svg>` DOM node into an `ImageData` pixel buffer.
///
/// Returns `None` if the node is not a valid `<svg>` or has no dimensions.
pub fn render_svg(node: &Node, default_width: u32, default_height: u32) -> Option<ImageData> {
    let tag = match &node.node_type {
        NodeType::Element(t) if t == "svg" => t,
        _ => return None,
    };
    let _ = tag;

    let width = get_attribute(node, "width")
        .and_then(|v| parse_dimension(&v))
        .unwrap_or(default_width);
    let height = get_attribute(node, "height")
        .and_then(|v| parse_dimension(&v))
        .unwrap_or(default_height);

    if width == 0 || height == 0 || width > 4096 || height > 4096 {
        return None;
    }

    let mut pixels = alloc::vec![0x00000000u32; (width as usize) * (height as usize)];

    // Process child SVG elements
    for child in &node.children {
        if let NodeType::Element(child_tag) = &child.node_type {
            match child_tag.as_str() {
                "rect" => draw_svg_rect(child, &mut pixels, width, height),
                "circle" => draw_svg_circle(child, &mut pixels, width, height),
                "line" => draw_svg_line(child, &mut pixels, width, height),
                "polyline" => draw_svg_polyline(child, &mut pixels, width, height),
                _ => {} // Unsupported elements are silently skipped
            }
        }
    }

    Some(ImageData { width, height, pixels })
}

fn draw_svg_rect(node: &Node, pixels: &mut [u32], canvas_w: u32, canvas_h: u32) {
    let x = attr_u32(node, "x").unwrap_or(0);
    let y = attr_u32(node, "y").unwrap_or(0);
    let w = attr_u32(node, "width").unwrap_or(0);
    let h = attr_u32(node, "height").unwrap_or(0);
    let fill = parse_svg_color(&get_attribute(node, "fill").unwrap_or_default()).unwrap_or(0xFF000000);

    let x1 = x.min(canvas_w);
    let y1 = y.min(canvas_h);
    let x2 = (x + w).min(canvas_w);
    let y2 = (y + h).min(canvas_h);

    for py in y1..y2 {
        for px in x1..x2 {
            pixels[(py * canvas_w + px) as usize] = fill;
        }
    }

    // Stroke outline if specified
    if let Some(stroke) = get_attribute(node, "stroke") {
        if let Some(color) = parse_svg_color(&stroke) {
            // Top/bottom edges
            for px in x1..x2 {
                if y1 < canvas_h { pixels[(y1 * canvas_w + px) as usize] = color; }
                if y2 > 0 && y2 - 1 < canvas_h { pixels[((y2 - 1) * canvas_w + px) as usize] = color; }
            }
            // Left/right edges
            for py in y1..y2 {
                if x1 < canvas_w { pixels[(py * canvas_w + x1) as usize] = color; }
                if x2 > 0 && x2 - 1 < canvas_w { pixels[(py * canvas_w + x2 - 1) as usize] = color; }
            }
        }
    }
}

fn draw_svg_circle(node: &Node, pixels: &mut [u32], canvas_w: u32, canvas_h: u32) {
    let cx = attr_i32(node, "cx").unwrap_or(0);
    let cy = attr_i32(node, "cy").unwrap_or(0);
    let r = attr_i32(node, "r").unwrap_or(0);
    let fill = parse_svg_color(&get_attribute(node, "fill").unwrap_or_default()).unwrap_or(0xFF000000);

    if r <= 0 {
        return;
    }

    let y0 = (cy - r).max(0) as u32;
    let y1 = ((cy + r) as u32).min(canvas_h);
    let x0 = (cx - r).max(0) as u32;
    let x1 = ((cx + r) as u32).min(canvas_w);
    let r_sq = (r * r) as i64;

    for py in y0..y1 {
        for px in x0..x1 {
            let dx = px as i32 - cx;
            let dy = py as i32 - cy;
            if (dx as i64 * dx as i64 + dy as i64 * dy as i64) <= r_sq {
                pixels[(py * canvas_w + px) as usize] = fill;
            }
        }
    }
}

fn draw_svg_line(node: &Node, pixels: &mut [u32], canvas_w: u32, canvas_h: u32) {
    let x1 = attr_i32(node, "x1").unwrap_or(0);
    let y1 = attr_i32(node, "y1").unwrap_or(0);
    let x2 = attr_i32(node, "x2").unwrap_or(0);
    let y2 = attr_i32(node, "y2").unwrap_or(0);
    let color = parse_svg_color(&get_attribute(node, "stroke").unwrap_or_default()).unwrap_or(0xFF000000);

    bresenham_line(x1, y1, x2, y2, color, pixels, canvas_w, canvas_h);
}

fn draw_svg_polyline(node: &Node, pixels: &mut [u32], canvas_w: u32, canvas_h: u32) {
    let points_str = match get_attribute(node, "points") {
        Some(s) => s,
        None => return,
    };
    let color = parse_svg_color(&get_attribute(node, "stroke").unwrap_or_default()).unwrap_or(0xFF000000);

    let coords: Vec<(i32, i32)> = parse_points(&points_str);

    for i in 1..coords.len() {
        bresenham_line(coords[i-1].0, coords[i-1].1, coords[i].0, coords[i].1, color, pixels, canvas_w, canvas_h);
    }
}

/// Bresenham's line algorithm.
fn bresenham_line(x0: i32, y0: i32, x1: i32, y1: i32, color: u32, pixels: &mut [u32], w: u32, h: u32) {
    let mut x = x0;
    let mut y = y0;
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx: i32 = if x0 < x1 { 1 } else { -1 };
    let sy: i32 = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;

    loop {
        if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
            pixels[(y as u32 * w + x as u32) as usize] = color;
        }
        if x == x1 && y == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            err += dx;
            y += sy;
        }
    }
}

/// Parse SVG `points` attribute: "x1,y1 x2,y2 x3,y3"
fn parse_points(s: &str) -> Vec<(i32, i32)> {
    let mut result = Vec::new();
    for pair in s.split_whitespace() {
        let parts: Vec<&str> = pair.split(',').collect();
        if parts.len() == 2 {
            if let (Some(x), Some(y)) = (parse_i32(parts[0]), parse_i32(parts[1])) {
                result.push((x, y));
            }
        }
    }
    result
}

/// Parse a CSS/SVG color value. Supports `#RRGGBB`, `#RGB`, and named colors.
pub fn parse_svg_color(s: &str) -> Option<u32> {
    let s = s.trim();
    if s.is_empty() || s == "none" {
        return None;
    }
    parse_css_color(s)
}

/// Parse a CSS color: `#RRGGBB`, `#RGB`, or named keyword.
pub fn parse_css_color(s: &str) -> Option<u32> {
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

    // Named CSS color keywords
    match s.to_ascii_lowercase().as_str() {
        "black"   => Some(0xFF000000),
        "white"   => Some(0xFFFFFFFF),
        "red"     => Some(0xFFFF0000),
        "green"   => Some(0xFF008000),
        "blue"    => Some(0xFF0000FF),
        "yellow"  => Some(0xFFFFFF00),
        "cyan" | "aqua" => Some(0xFF00FFFF),
        "magenta" | "fuchsia" => Some(0xFFFF00FF),
        "orange"  => Some(0xFFFFA500),
        "purple"  => Some(0xFF800080),
        "gray" | "grey" => Some(0xFF808080),
        "silver"  => Some(0xFFC0C0C0),
        "navy"    => Some(0xFF000080),
        "teal"    => Some(0xFF008080),
        "maroon"  => Some(0xFF800000),
        "olive"   => Some(0xFF808000),
        "lime"    => Some(0xFF00FF00),
        "transparent" => Some(0x00000000),
        _ => None,
    }
}

fn attr_u32(node: &Node, name: &str) -> Option<u32> {
    get_attribute(node, name).and_then(|v| parse_dimension(&v))
}

fn attr_i32(node: &Node, name: &str) -> Option<i32> {
    get_attribute(node, name).and_then(|v| parse_i32(&v))
}

/// Parse a dimension string, stripping trailing "px" if present.
fn parse_dimension(s: &str) -> Option<u32> {
    let s = s.trim().trim_end_matches("px");
    s.parse::<u32>().ok()
}

fn parse_i32(s: &str) -> Option<i32> {
    s.trim().trim_end_matches("px").parse::<i32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn make_svg_node(width: u32, height: u32, children: Vec<Node>) -> Node {
        Node {
            node_type: NodeType::Element("svg".to_string()),
            children,
            attributes: alloc::vec![
                ("width".to_string(), width.to_string()),
                ("height".to_string(), height.to_string()),
            ],
        }
    }

    fn make_element(tag: &str, attrs: Vec<(&str, &str)>) -> Node {
        Node {
            node_type: NodeType::Element(String::from(tag)),
            children: Vec::new(),
            attributes: attrs.iter().map(|(k, v)| (String::from(*k), String::from(*v))).collect(),
        }
    }

    #[test]
    fn test_render_svg_empty() {
        let svg = make_svg_node(100, 100, Vec::new());
        let result = render_svg(&svg, 200, 200);
        assert!(result.is_some());
        let img = result.unwrap();
        assert_eq!(img.width, 100);
        assert_eq!(img.height, 100);
        // All pixels should be transparent
        assert!(img.pixels.iter().all(|&p| p == 0x00000000));
    }

    #[test]
    fn test_render_svg_rect() {
        let rect = make_element("rect", alloc::vec![
            ("x", "0"), ("y", "0"), ("width", "10"), ("height", "10"), ("fill", "red"),
        ]);
        let svg = make_svg_node(20, 20, alloc::vec![rect]);
        let img = render_svg(&svg, 100, 100).unwrap();
        // Top-left pixel should be red
        assert_eq!(img.pixels[0], 0xFFFF0000);
        // Pixel at (15, 15) should be transparent
        assert_eq!(img.pixels[15 * 20 + 15], 0x00000000);
    }

    #[test]
    fn test_render_svg_circle() {
        let circle = make_element("circle", alloc::vec![
            ("cx", "10"), ("cy", "10"), ("r", "5"), ("fill", "blue"),
        ]);
        let svg = make_svg_node(20, 20, alloc::vec![circle]);
        let img = render_svg(&svg, 100, 100).unwrap();
        // Center should be blue
        assert_eq!(img.pixels[10 * 20 + 10], 0xFF0000FF);
        // Corner should be transparent
        assert_eq!(img.pixels[0], 0x00000000);
    }

    #[test]
    fn test_render_svg_line() {
        let line = make_element("line", alloc::vec![
            ("x1", "0"), ("y1", "0"), ("x2", "9"), ("y2", "0"), ("stroke", "#FF0000"),
        ]);
        let svg = make_svg_node(10, 10, alloc::vec![line]);
        let img = render_svg(&svg, 100, 100).unwrap();
        // All pixels along y=0 should be red
        for x in 0..10u32 {
            assert_eq!(img.pixels[x as usize], 0xFFFF0000);
        }
    }

    #[test]
    fn test_parse_css_color_hex() {
        assert_eq!(parse_css_color("#FF0000"), Some(0xFFFF0000));
        assert_eq!(parse_css_color("#00ff00"), Some(0xFF00FF00));
        assert_eq!(parse_css_color("#F00"), Some(0xFFFF0000));
    }

    #[test]
    fn test_parse_css_color_names() {
        assert_eq!(parse_css_color("red"), Some(0xFFFF0000));
        assert_eq!(parse_css_color("blue"), Some(0xFF0000FF));
        assert_eq!(parse_css_color("transparent"), Some(0x00000000));
        assert_eq!(parse_css_color("none"), None);
        assert_eq!(parse_css_color(""), None);
    }

    #[test]
    fn test_parse_points() {
        let pts = parse_points("10,20 30,40 50,60");
        assert_eq!(pts, alloc::vec![(10, 20), (30, 40), (50, 60)]);
    }

    #[test]
    fn test_render_svg_not_svg_node() {
        let div = Node {
            node_type: NodeType::Element("div".to_string()),
            children: Vec::new(),
            attributes: Vec::new(),
        };
        assert!(render_svg(&div, 100, 100).is_none());
    }

    #[test]
    fn test_render_svg_oversized_rejected() {
        let svg = make_svg_node(5000, 5000, Vec::new());
        assert!(render_svg(&svg, 100, 100).is_none());
    }

    #[test]
    fn test_render_svg_polyline() {
        let polyline = make_element("polyline", alloc::vec![
            ("points", "0,0 5,0 5,5"), ("stroke", "white"),
        ]);
        let svg = make_svg_node(10, 10, alloc::vec![polyline]);
        let img = render_svg(&svg, 100, 100).unwrap();
        // (0,0) should have stroke
        assert_eq!(img.pixels[0], 0xFFFFFFFF);
        // (5,0) should have stroke
        assert_eq!(img.pixels[5], 0xFFFFFFFF);
    }
}
