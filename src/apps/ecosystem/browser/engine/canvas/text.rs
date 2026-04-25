extern crate alloc;
use crate::apps::ecosystem::browser::engine::fonts;
use alloc::string::String;

pub struct CanvasText {
    pub font_family: String,
    pub font_size: u32,
}

impl CanvasText {
    pub fn new() -> Self {
        Self { font_family: String::from("sans-serif"), font_size: 10 }
    }

    pub fn measure_text(&self, text: &str) -> TextMetrics {
        let metrics = fonts::match_font_family(&self.font_family);
        TextMetrics { width: metrics.line_width(text.len()) as f64 }
    }

    pub fn set_font(&mut self, font: &str) {
        for part in font.split_whitespace() {
            if let Ok(size) = part.trim_end_matches("px").parse::<u32>() {
                self.font_size = size;
            } else {
                self.font_family = String::from(part);
            }
        }
    }
}

pub struct TextMetrics {
    pub width: f64,
}
