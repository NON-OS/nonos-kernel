extern crate alloc;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub enum PathCommand {
    MoveTo(f64, f64),
    LineTo(f64, f64),
    Arc(f64, f64, f64, f64, f64),
    BezierCurveTo(f64, f64, f64, f64, f64, f64),
    QuadraticCurveTo(f64, f64, f64, f64),
    ClosePath,
}

pub struct CanvasPath {
    pub commands: Vec<PathCommand>,
    pub current_x: f64,
    pub current_y: f64,
}

impl CanvasPath {
    pub fn new() -> Self { Self { commands: Vec::new(), current_x: 0.0, current_y: 0.0 } }

    pub fn begin_path(&mut self) { self.commands.clear(); }

    pub fn move_to(&mut self, x: f64, y: f64) {
        self.commands.push(PathCommand::MoveTo(x, y));
        self.current_x = x;
        self.current_y = y;
    }

    pub fn line_to(&mut self, x: f64, y: f64) {
        self.commands.push(PathCommand::LineTo(x, y));
        self.current_x = x;
        self.current_y = y;
    }

    pub fn arc(&mut self, x: f64, y: f64, radius: f64, start_angle: f64, end_angle: f64) {
        self.commands.push(PathCommand::Arc(x, y, radius, start_angle, end_angle));
    }

    pub fn bezier_curve_to(&mut self, cp1x: f64, cp1y: f64, cp2x: f64, cp2y: f64, x: f64, y: f64) {
        self.commands.push(PathCommand::BezierCurveTo(cp1x, cp1y, cp2x, cp2y, x, y));
        self.current_x = x;
        self.current_y = y;
    }

    pub fn quadratic_curve_to(&mut self, cpx: f64, cpy: f64, x: f64, y: f64) {
        self.commands.push(PathCommand::QuadraticCurveTo(cpx, cpy, x, y));
        self.current_x = x;
        self.current_y = y;
    }

    pub fn close_path(&mut self) { self.commands.push(PathCommand::ClosePath); }
}
