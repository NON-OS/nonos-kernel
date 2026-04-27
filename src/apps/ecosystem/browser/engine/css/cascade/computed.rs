use super::super::properties::*;
use super::super::types::{CssColor, CssValue};

#[derive(Debug, Clone)]
pub struct ComputedStyle {
    pub display: Display,
    pub position: Position,
    pub box_sizing: BoxSizing,
    pub width: CssValue,
    pub height: CssValue,
    pub min_width: CssValue,
    pub max_width: CssValue,
    pub min_height: CssValue,
    pub max_height: CssValue,
    pub margin_top: CssValue,
    pub margin_right: CssValue,
    pub margin_bottom: CssValue,
    pub margin_left: CssValue,
    pub padding_top: CssValue,
    pub padding_right: CssValue,
    pub padding_bottom: CssValue,
    pub padding_left: CssValue,
    pub border_top_width: CssValue,
    pub border_right_width: CssValue,
    pub border_bottom_width: CssValue,
    pub border_left_width: CssValue,
    pub border_top_style: BorderStyle,
    pub border_top_color: Option<CssColor>,
    pub color: Option<CssColor>,
    pub background_color: Option<CssColor>,
    pub font_size: CssValue,
    pub font_weight: FontWeight,
    pub font_style: FontStyle,
    pub text_decoration: TextDecoration,
    pub text_align: TextAlign,
    pub line_height: CssValue,
    pub white_space: WhiteSpace,
    pub visibility: Visibility,
    pub opacity: f32,
    pub overflow: Overflow,
    pub float: Float,
    pub clear: Clear,
    pub top: CssValue,
    pub right: CssValue,
    pub bottom: CssValue,
    pub left: CssValue,
    pub z_index: CssValue,
    pub flex_direction: FlexDirection,
    pub flex_wrap: FlexWrap,
    pub justify_content: JustifyContent,
    pub align_items: AlignItems,
    pub flex_grow: f32,
    pub flex_shrink: f32,
    pub flex_basis: CssValue,
    pub order: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TextAlign {
    #[default]
    Left,
    Center,
    Right,
    Justify,
}

impl TextAlign {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "center" => Self::Center,
            "right" => Self::Right,
            "justify" => Self::Justify,
            _ => Self::Left,
        }
    }
}
