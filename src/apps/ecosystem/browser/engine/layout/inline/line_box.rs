extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct LineBox {
    pub fragments: Vec<InlineFragment>,
    pub y: f32,
    pub height: f32,
    pub width: f32,
}

#[derive(Debug, Clone)]
pub struct InlineFragment {
    pub text: String,
    pub x: f32,
    pub width: f32,
    pub node_index: Option<u32>,
    pub is_link: bool,
    pub href: Option<String>,
}

impl LineBox {
    pub fn new(y: f32, line_height: f32) -> Self {
        Self { fragments: Vec::new(), y, height: line_height, width: 0.0 }
    }

    pub fn remaining_width(&self, container_width: f32) -> f32 {
        container_width - self.width
    }

    pub fn add_fragment(&mut self, text: String, char_width: f32, node_index: Option<u32>) {
        let frag_width = text.len() as f32 * char_width;
        let fragment = InlineFragment {
            text,
            x: self.width,
            width: frag_width,
            node_index,
            is_link: false,
            href: None,
        };
        self.width += frag_width;
        self.fragments.push(fragment);
    }
}
