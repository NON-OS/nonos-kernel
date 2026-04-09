extern crate alloc;
use alloc::vec::Vec;
use super::transform::CanvasTransform;
use super::style::CanvasStyle;

pub struct SavedState {
    pub transform: CanvasTransform,
    pub fill_style: CanvasStyle,
    pub stroke_style: CanvasStyle,
    pub line_width: f64,
    pub global_alpha: f64,
}

pub struct CanvasState {
    stack: Vec<SavedState>,
}

impl CanvasState {
    pub fn new() -> Self { Self { stack: Vec::new() } }

    pub fn save(&mut self, transform: &CanvasTransform, fill: &CanvasStyle, stroke: &CanvasStyle, line_width: f64, alpha: f64) {
        self.stack.push(SavedState {
            transform: CanvasTransform { a: transform.a, b: transform.b, c: transform.c, d: transform.d, e: transform.e, f: transform.f },
            fill_style: fill.clone(),
            stroke_style: stroke.clone(),
            line_width,
            global_alpha: alpha,
        });
    }

    pub fn restore(&mut self) -> Option<SavedState> { self.stack.pop() }

    pub fn depth(&self) -> usize { self.stack.len() }
}
