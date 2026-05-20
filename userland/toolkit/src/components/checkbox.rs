use crate::design::color::Argb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckboxStyle {
    pub on: Argb,
    pub off: Argb,
}

impl Default for CheckboxStyle {
    fn default() -> Self {
        Self {
            on: Argb::from_channels(0xFF, 0x32, 0xA8, 0x6B),
            off: Argb::from_channels(0xFF, 0x2A, 0x2F, 0x3A),
        }
    }
}

pub fn checkbox_color(checked: bool, style: CheckboxStyle) -> u32 {
    if checked {
        style.on.as_u32()
    } else {
        style.off.as_u32()
    }
}
