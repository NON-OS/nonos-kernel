extern crate alloc;
use alloc::vec::Vec;

pub struct CanvasDrawing {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
}

impl CanvasDrawing {
    pub fn new(width: u32, height: u32) -> Self {
        let pixels = alloc::vec![0u32; (width * height) as usize];
        Self { width, height, pixels }
    }

    pub fn fill_rect(&mut self, x: i32, y: i32, w: u32, h: u32, color: u32) {
        for row in 0..h as i32 {
            for col in 0..w as i32 {
                self.set_pixel(x + col, y + row, color);
            }
        }
    }

    pub fn stroke_rect(&mut self, x: i32, y: i32, w: u32, h: u32, color: u32) {
        for col in 0..w as i32 { self.set_pixel(x + col, y, color); self.set_pixel(x + col, y + h as i32 - 1, color); }
        for row in 0..h as i32 { self.set_pixel(x, y + row, color); self.set_pixel(x + w as i32 - 1, y + row, color); }
    }

    pub fn clear_rect(&mut self, x: i32, y: i32, w: u32, h: u32) {
        self.fill_rect(x, y, w, h, 0);
    }

    fn set_pixel(&mut self, x: i32, y: i32, color: u32) {
        if x >= 0 && y >= 0 && (x as u32) < self.width && (y as u32) < self.height {
            self.pixels[(y as u32 * self.width + x as u32) as usize] = color;
        }
    }

    pub fn get_pixel(&self, x: u32, y: u32) -> u32 {
        if x < self.width && y < self.height { self.pixels[(y * self.width + x) as usize] } else { 0 }
    }
}
