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

/// Text alignment for CSS `text-align` property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextAlign {
    #[default]
    Left,
    Center,
    Right,
}

#[derive(Debug, Clone)]
pub struct Document {
    pub title: String,
    pub root: Node,
    pub links: Vec<Link>,
    pub forms: Vec<Form>,
    pub images: Vec<Image>,
    /// CSS class selectors mapped to display value, e.g. ("hidden", "none")
    pub hidden_classes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub node_type: NodeType,
    pub children: Vec<Node>,
    pub attributes: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub enum NodeType {
    Element(String),
    Text(String),
    Comment(String),
}

#[derive(Debug, Clone)]
pub struct Link {
    pub href: String,
    pub text: String,
    pub rel: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub inputs: Vec<FormInput>,
}

#[derive(Debug, Clone)]
pub struct FormInput {
    pub name: String,
    pub input_type: String,
    pub value: String,
    pub placeholder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Image {
    pub src: String,
    pub alt: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// Decoded image pixel data (ARGB8888).
#[derive(Debug, Clone)]
pub struct ImageData {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct RenderLine {
    pub y: u32,
    pub elements: Vec<RenderElement>,
}

#[derive(Debug, Clone)]
pub struct RenderElement {
    pub x: u32,
    pub width: u32,
    pub content: RenderContent,
}

#[derive(Debug, Clone)]
pub enum RenderContent {
    Text { text: String, style: TextStyle },
    Link { text: String, href: String },
    Image { alt: String, width: u32, height: u32 },
    /// Decoded image with pixel data ready for blitting.
    DecodedImage { data: ImageData },
    Input { name: String, width: u32 },
    Button { text: String },
    /// Canvas element with rasterized pixel buffer.
    Canvas { data: ImageData },
    /// SVG element rasterized to pixel buffer.
    Svg { data: ImageData },
    LineBreak,
    HorizontalRule,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TextStyle {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub heading_level: u8,
    pub monospace: bool,
    pub bg_color: Option<u32>,
    pub color: Option<u32>,
    pub font_scale: u8,
    pub text_align: TextAlign,
}

#[derive(Debug, Clone)]
pub struct RenderOutput {
    pub lines: Vec<RenderLine>,
    pub total_height: u32,
    pub links: Vec<(u32, u32, u32, u32, String)>,
}

/// Canvas 2D drawing context that rasterizes to an `ImageData` pixel buffer.
#[derive(Debug, Clone)]
pub struct CanvasContext2D {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
    pub fill_color: u32,
    pub stroke_color: u32,
}

impl CanvasContext2D {
    pub fn new(width: u32, height: u32) -> Self {
        let pixels = alloc::vec![0x00000000; (width as usize) * (height as usize)];
        Self {
            width,
            height,
            pixels,
            fill_color: 0xFF000000,
            stroke_color: 0xFF000000,
        }
    }

    pub fn set_fill_color(&mut self, color: u32) {
        self.fill_color = color;
    }

    pub fn set_stroke_color(&mut self, color: u32) {
        self.stroke_color = color;
    }

    pub fn fill_rect(&mut self, x: i32, y: i32, w: u32, h: u32) {
        let x0 = x.max(0) as u32;
        let y0 = y.max(0) as u32;
        let x1 = ((x as i64 + w as i64) as u32).min(self.width);
        let y1 = ((y as i64 + h as i64) as u32).min(self.height);
        for py in y0..y1 {
            for px in x0..x1 {
                self.pixels[(py * self.width + px) as usize] = self.fill_color;
            }
        }
    }

    pub fn stroke_rect(&mut self, x: i32, y: i32, w: u32, h: u32) {
        let x0 = x.max(0) as u32;
        let y0 = y.max(0) as u32;
        let x1 = ((x as i64 + w as i64) as u32).min(self.width);
        let y1 = ((y as i64 + h as i64) as u32).min(self.height);
        // Top and bottom edges
        for px in x0..x1 {
            if y0 < self.height {
                self.pixels[(y0 * self.width + px) as usize] = self.stroke_color;
            }
            if y1 > 0 && y1 - 1 < self.height {
                self.pixels[((y1 - 1) * self.width + px) as usize] = self.stroke_color;
            }
        }
        // Left and right edges
        for py in y0..y1 {
            if x0 < self.width {
                self.pixels[(py * self.width + x0) as usize] = self.stroke_color;
            }
            if x1 > 0 && x1 - 1 < self.width {
                self.pixels[(py * self.width + x1 - 1) as usize] = self.stroke_color;
            }
        }
    }

    pub fn clear_rect(&mut self, x: i32, y: i32, w: u32, h: u32) {
        let x0 = x.max(0) as u32;
        let y0 = y.max(0) as u32;
        let x1 = ((x as i64 + w as i64) as u32).min(self.width);
        let y1 = ((y as i64 + h as i64) as u32).min(self.height);
        for py in y0..y1 {
            for px in x0..x1 {
                self.pixels[(py * self.width + px) as usize] = 0x00000000;
            }
        }
    }

    pub fn fill_text(&mut self, text: &str, x: u32, y: u32) {
        // Simple 8-pixel-wide character rendering into the pixel buffer
        let char_w: u32 = 8;
        let char_h: u32 = 16;
        let mut cx = x;
        for _ch in text.chars() {
            if cx + char_w > self.width || y + char_h > self.height {
                break;
            }
            // Render a simple filled block per character (no font rasterizer in canvas)
            for py in y..y + char_h {
                for px in cx..cx + char_w {
                    self.pixels[(py * self.width + px) as usize] = self.fill_color;
                }
            }
            cx += char_w;
        }
    }

    pub fn to_image_data(&self) -> ImageData {
        ImageData {
            width: self.width,
            height: self.height,
            pixels: self.pixels.clone(),
        }
    }
}

/// Animation state for tick-based CSS transitions.
#[derive(Debug, Clone)]
pub struct AnimationState {
    pub start_ms: u64,
    pub duration_ms: u64,
    pub property: AnimatedProperty,
}

/// Animatable CSS properties.
#[derive(Debug, Clone, Copy)]
pub enum AnimatedProperty {
    Opacity { from: u8, to: u8 },
    TranslateX { from: i32, to: i32 },
    TranslateY { from: i32, to: i32 },
}

impl AnimationState {
    pub fn new(start_ms: u64, duration_ms: u64, property: AnimatedProperty) -> Self {
        Self { start_ms, duration_ms, property }
    }

    /// Returns the progress ratio 0..=255 (fixed-point 0.0..=1.0).
    pub fn progress(&self, now_ms: u64) -> u8 {
        if now_ms <= self.start_ms {
            return 0;
        }
        let elapsed = now_ms - self.start_ms;
        if elapsed >= self.duration_ms {
            return 255;
        }
        ((elapsed * 255) / self.duration_ms) as u8
    }

    pub fn is_complete(&self, now_ms: u64) -> bool {
        now_ms >= self.start_ms + self.duration_ms
    }

    /// Interpolate the current value of the animated property.
    pub fn current_value(&self, now_ms: u64) -> AnimatedProperty {
        let p = self.progress(now_ms) as i32;
        match self.property {
            AnimatedProperty::Opacity { from, to } => {
                let v = from as i32 + ((to as i32 - from as i32) * p) / 255;
                AnimatedProperty::Opacity { from: v as u8, to: v as u8 }
            }
            AnimatedProperty::TranslateX { from, to } => {
                let v = from + ((to - from) * p) / 255;
                AnimatedProperty::TranslateX { from: v, to: v }
            }
            AnimatedProperty::TranslateY { from, to } => {
                let v = from + ((to - from) * p) / 255;
                AnimatedProperty::TranslateY { from: v, to: v }
            }
        }
    }
}
