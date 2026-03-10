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

#[derive(Debug, Clone)]
pub struct Document {
    pub title: String,
    pub root: Node,
    pub links: Vec<Link>,
    pub forms: Vec<Form>,
    pub images: Vec<Image>,
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
    Input { name: String, width: u32 },
    Button { text: String },
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
}

#[derive(Debug, Clone)]
pub struct RenderOutput {
    pub lines: Vec<RenderLine>,
    pub total_height: u32,
    pub links: Vec<(u32, u32, u32, u32, String)>,
}
