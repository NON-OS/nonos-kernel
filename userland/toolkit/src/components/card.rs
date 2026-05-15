use crate::design::{border::Border, color::Argb, shadow::Shadow};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CardStyle {
    pub bg: Argb,
    pub border: Border,
    pub shadow: Shadow,
}

impl Default for CardStyle {
    fn default() -> Self {
        Self {
            bg: Argb::from_channels(0xFF, 0x16, 0x1D, 0x28),
            border: Border::none(),
            shadow: Shadow::sm(),
        }
    }
}
