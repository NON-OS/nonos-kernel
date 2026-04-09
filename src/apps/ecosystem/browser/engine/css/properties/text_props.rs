#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FontWeight {
    #[default]
    Normal,
    Bold,
    Bolder,
    Lighter,
    W100,
    W200,
    W300,
    W400,
    W500,
    W600,
    W700,
    W800,
    W900,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FontStyle {
    #[default]
    Normal,
    Italic,
    Oblique,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TextDecoration {
    #[default]
    None,
    Underline,
    Overline,
    LineThrough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WhiteSpace {
    #[default]
    Normal,
    NoWrap,
    Pre,
    PreWrap,
    PreLine,
}

impl FontWeight {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "bold" => Self::Bold,
            "bolder" => Self::Bolder,
            "lighter" => Self::Lighter,
            "100" => Self::W100,
            "200" => Self::W200,
            "300" => Self::W300,
            "400" | "normal" => Self::Normal,
            "500" => Self::W500,
            "600" => Self::W600,
            "700" => Self::W700,
            "800" => Self::W800,
            "900" => Self::W900,
            _ => Self::Normal,
        }
    }

    pub fn is_bold(&self) -> bool {
        matches!(self, Self::Bold | Self::Bolder | Self::W700 | Self::W800 | Self::W900)
    }
}
