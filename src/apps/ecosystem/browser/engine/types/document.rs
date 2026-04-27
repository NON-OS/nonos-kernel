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

use super::form::{Form, Link};
use super::image::Image;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Document {
    pub title: String,
    pub root: Node,
    pub links: Vec<Link>,
    pub forms: Vec<Form>,
    pub images: Vec<Image>,
    pub hidden_classes: Vec<String>,
    pub centered_classes: Vec<String>,
    /// URL from `<meta http-equiv="refresh">` inside a `<noscript>` block.
    pub noscript_redirect: Option<String>,
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
