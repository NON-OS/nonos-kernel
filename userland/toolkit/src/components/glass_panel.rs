use crate::design::color::Argb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlassStyle {
    pub tint: Argb,
    pub border: Argb,
}

impl Default for GlassStyle {
    fn default() -> Self {
        Self {
            tint: Argb::from_channels(0x66, 0xC8, 0xD7, 0xEA),
            border: Argb::from_channels(0x80, 0xF2, 0xF7, 0xFD),
        }
    }
}
