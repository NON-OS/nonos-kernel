use crate::design::color::Argb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TooltipStyle {
    pub bg: Argb,
    pub fg: Argb,
}

impl Default for TooltipStyle {
    fn default() -> Self {
        Self {
            bg: Argb::from_channels(0xF0, 0x14, 0x19, 0x22),
            fg: Argb::from_channels(0xFF, 0xF0, 0xF4, 0xF9),
        }
    }
}
