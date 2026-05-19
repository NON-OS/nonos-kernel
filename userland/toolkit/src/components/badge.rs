use crate::design::color::Argb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BadgeStyle {
    pub bg: Argb,
    pub fg: Argb,
}

impl Default for BadgeStyle {
    fn default() -> Self {
        Self { bg: Argb::from_channels(0xFF, 0x26, 0x6D, 0xB8), fg: Argb::WHITE }
    }
}
