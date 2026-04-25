use super::super::super::css::types::CssColor;
use super::super::types::LayoutBox;

pub struct TextPaintCommand {
    pub x: f32,
    pub y: f32,
    pub color: CssColor,
    pub font_size: f32,
    pub bold: bool,
    pub italic: bool,
}

pub fn paint_text(layout_box: &LayoutBox) -> TextPaintCommand {
    let color = layout_box.style.color.unwrap_or(CssColor::rgb(0, 0, 0));
    let font_size = layout_box.style.font_size.to_px().unwrap_or(16.0);
    let bold = layout_box.style.font_weight.is_bold();
    let italic = matches!(
        layout_box.style.font_style,
        super::super::super::css::properties::FontStyle::Italic
    );

    TextPaintCommand {
        x: layout_box.dimensions.content.x,
        y: layout_box.dimensions.content.y,
        color,
        font_size,
        bold,
        italic,
    }
}
