extern crate alloc;

#[derive(Debug, Clone)]
pub enum CanvasStyle {
    Color(u32),
    Gradient(Gradient),
}

#[derive(Debug, Clone)]
pub struct Gradient {
    pub kind: GradientKind,
    pub stops: alloc::vec::Vec<ColorStop>,
}

#[derive(Debug, Clone, Copy)]
pub enum GradientKind {
    Linear { x0: f64, y0: f64, x1: f64, y1: f64 },
    Radial { x0: f64, y0: f64, r0: f64, x1: f64, y1: f64, r1: f64 },
}

#[derive(Debug, Clone, Copy)]
pub struct ColorStop {
    pub offset: f64,
    pub color: u32,
}

impl CanvasStyle {
    pub fn from_css_color(s: &str) -> Self {
        Self::Color(parse_color_simple(s))
    }
}

fn parse_color_simple(s: &str) -> u32 {
    match s {
        "black" => 0xFF00_0000,
        "white" => 0xFFFF_FFFF,
        "red" => 0xFFFF_0000,
        "green" => 0xFF00_8000,
        "blue" => 0xFF00_00FF,
        "yellow" => 0xFFFF_FF00,
        "transparent" => 0x0000_0000,
        _ if s.starts_with('#') && s.len() == 7 => {
            let r = u8::from_str_radix(&s[1..3], 16).unwrap_or(0) as u32;
            let g = u8::from_str_radix(&s[3..5], 16).unwrap_or(0) as u32;
            let b = u8::from_str_radix(&s[5..7], 16).unwrap_or(0) as u32;
            0xFF00_0000 | (r << 16) | (g << 8) | b
        }
        _ => 0xFF00_0000,
    }
}

impl Gradient {
    pub fn add_color_stop(&mut self, offset: f64, color: u32) {
        self.stops.push(ColorStop { offset, color });
        self.stops
            .sort_by(|a, b| a.offset.partial_cmp(&b.offset).unwrap_or(core::cmp::Ordering::Equal));
    }
}
