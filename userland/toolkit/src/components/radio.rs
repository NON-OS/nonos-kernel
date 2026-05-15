use crate::design::color::Argb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RadioStyle { pub active: Argb, pub inactive: Argb }

impl Default for RadioStyle {
    fn default() -> Self {
        Self { active: Argb::from_channels(0xFF, 0x46, 0xB2, 0xE0), inactive: Argb::from_channels(0xFF, 0x33, 0x3A, 0x49) }
    }
}

pub fn radio_color(selected: bool, style: RadioStyle) -> u32 {
    if selected { style.active.as_u32() } else { style.inactive.as_u32() }
}
