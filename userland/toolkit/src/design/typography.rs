#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FontWeight {
    Regular,
    Medium,
    Bold,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextStyle {
    pub px: u8,
    pub weight: FontWeight,
    pub letter_spacing: i8,
    pub line_height: u8,
}

impl TextStyle {
    pub const fn caption() -> Self {
        Self { px: 11, weight: FontWeight::Regular, letter_spacing: 0, line_height: 14 }
    }

    pub const fn body() -> Self {
        Self { px: 13, weight: FontWeight::Regular, letter_spacing: 0, line_height: 18 }
    }

    pub const fn title() -> Self {
        Self { px: 18, weight: FontWeight::Medium, letter_spacing: 0, line_height: 24 }
    }

    pub const fn headline() -> Self {
        Self { px: 24, weight: FontWeight::Bold, letter_spacing: 0, line_height: 30 }
    }
}
