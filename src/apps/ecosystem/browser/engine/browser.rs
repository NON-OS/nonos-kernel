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
use super::types::{Document, Node, NodeType};
use super::parser::parse_html;
use crate::apps::ecosystem::browser::js::JsRuntime;

pub struct BrowserEngine {
    document: Option<Document>,
    viewport_width: u32,
    viewport_height: u32,
    scroll_x: u32,
    scroll_y: u32,
    js_runtime: JsRuntime,
}

impl BrowserEngine {
    pub fn new(viewport_width: u32, viewport_height: u32) -> Self {
        Self { document: None, viewport_width, viewport_height, scroll_x: 0, scroll_y: 0, js_runtime: JsRuntime::new() }
    }
    pub fn set_viewport(&mut self, width: u32, height: u32) { self.viewport_width = width; self.viewport_height = height; }
    pub fn scroll_to(&mut self, x: u32, y: u32) { self.scroll_x = x; self.scroll_y = y; }
    pub fn scroll_by(&mut self, dx: i32, dy: i32) { self.scroll_x = (self.scroll_x as i32 + dx).max(0) as u32; self.scroll_y = (self.scroll_y as i32 + dy).max(0) as u32; }
    pub fn load_html(&mut self, html: &str) -> &Document {
        let document = parse_html(html);
        self.document = Some(document);
        self.scroll_x = 0;
        self.scroll_y = 0;
        self.execute_scripts();
        self.document.as_ref().expect("document just set")
    }
    pub fn document(&self) -> Option<&Document> { self.document.as_ref() }
    pub fn title(&self) -> Option<&str> { self.document.as_ref().map(|d| d.title.as_str()) }
    pub fn execute_js(&mut self, script: &str) { let _ = self.js_runtime.execute(script); }
    fn execute_scripts(&mut self) {
        let scripts = self.collect_scripts();
        for script in scripts { let _ = self.js_runtime.execute(&script); }
    }
    fn collect_scripts(&self) -> Vec<String> {
        let mut scripts = Vec::new();
        if let Some(doc) = &self.document { Self::find_scripts(&doc.root, &mut scripts); }
        scripts
    }
    fn find_scripts(node: &Node, scripts: &mut Vec<String>) {
        if let NodeType::Element(tag) = &node.node_type {
            if tag == "script" {
                let mut text = String::new();
                for child in &node.children { if let NodeType::Text(t) = &child.node_type { text.push_str(t); } }
                if !text.is_empty() { scripts.push(text); }
            }
        }
        for child in &node.children { Self::find_scripts(child, scripts); }
    }
}
