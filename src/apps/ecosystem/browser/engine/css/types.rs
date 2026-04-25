extern crate alloc;
use alloc::string::String;

#[derive(Debug, Clone, PartialEq)]
pub enum CssValue {
    Length(f32, Unit),
    Color(CssColor),
    Keyword(String),
    Number(f32),
    Percentage(f32),
    Auto,
    None,
    Inherit,
    Initial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unit {
    Px,
    Em,
    Rem,
    Percent,
    Vw,
    Vh,
    Pt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CssColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl CssColor {
    pub fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    pub fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    pub fn to_u32(self) -> u32 {
        (self.a as u32) << 24 | (self.r as u32) << 16 | (self.g as u32) << 8 | (self.b as u32)
    }
}

impl CssValue {
    pub fn is_auto(&self) -> bool {
        matches!(self, CssValue::Auto)
    }

    pub fn to_px(&self) -> Option<f32> {
        match self {
            CssValue::Length(v, Unit::Px) => Some(*v),
            CssValue::Number(v) => Some(*v),
            _ => Option::None,
        }
    }
}
