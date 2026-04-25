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

use super::align::TextAlign;
use super::image::ImageData;
use alloc::string::String;
use alloc::vec::Vec;

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
    Image { alt: String, width: u32, height: u32, src: String },
    DecodedImage { data: ImageData },
    Input { name: String, width: u32 },
    Button { text: String },
    Select { name: String, value: String },
    Textarea { name: String, width: u32, height: u32 },
    Canvas { data: ImageData },
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
    /// URL from `<meta http-equiv="refresh">` inside `<noscript>`, if any.
    pub noscript_redirect: Option<String>,
}
