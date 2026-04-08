use super::super::types::LayoutBox;
use super::super::super::css::types::CssColor;

pub struct PaintCommand {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub color: CssColor,
}

pub fn paint_background(layout_box: &LayoutBox) -> Option<PaintCommand> {
    let color = layout_box.style.background_color?;
    let border_box = layout_box.dimensions.border_box();
    Some(PaintCommand {
        x: border_box.x,
        y: border_box.y,
        width: border_box.width,
        height: border_box.height,
        color,
    })
}
