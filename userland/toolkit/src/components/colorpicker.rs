use crate::design::color::Argb;

pub fn gradient_color(x: u8, y: u8) -> Argb {
    let r = x;
    let g = y;
    let b = 255u8.saturating_sub(((x as u16 + y as u16) / 2) as u8);
    Argb::from_channels(0xFF, r, g, b)
}
