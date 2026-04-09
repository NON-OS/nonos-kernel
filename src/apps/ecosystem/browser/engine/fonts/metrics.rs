#[derive(Debug, Clone, Copy)]
pub struct FontMetrics {
    pub char_width: u32,
    pub char_height: u32,
    pub ascent: u32,
    pub descent: u32,
    pub line_height: u32,
}

impl FontMetrics {
    pub fn line_width(&self, char_count: usize) -> u32 {
        self.char_width * char_count as u32
    }

    pub fn total_height(&self) -> u32 { self.ascent + self.descent }
}
