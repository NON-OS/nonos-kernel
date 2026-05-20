#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Insets {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

impl Insets {
    pub const fn uniform(px: u16) -> Self {
        Self { left: px, top: px, right: px, bottom: px }
    }

    pub const fn hv(horizontal: u16, vertical: u16) -> Self {
        Self { left: horizontal, top: vertical, right: horizontal, bottom: vertical }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpacingScale {
    pub xs: u16,
    pub sm: u16,
    pub md: u16,
    pub lg: u16,
    pub xl: u16,
}

impl Default for SpacingScale {
    fn default() -> Self {
        Self { xs: 4, sm: 8, md: 12, lg: 16, xl: 24 }
    }
}
