use crate::design::color::Argb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Radius {
    pub top_left: u16,
    pub top_right: u16,
    pub bottom_right: u16,
    pub bottom_left: u16,
}

impl Radius {
    pub const fn uniform(px: u16) -> Self {
        Self { top_left: px, top_right: px, bottom_right: px, bottom_left: px }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Border {
    pub width: u16,
    pub color: Argb,
    pub radius: Radius,
}

impl Border {
    pub const fn none() -> Self {
        Self { width: 0, color: Argb::TRANSPARENT, radius: Radius::uniform(0) }
    }

    pub const fn hairline(color: Argb, radius: Radius) -> Self {
        Self { width: 1, color, radius }
    }
}
