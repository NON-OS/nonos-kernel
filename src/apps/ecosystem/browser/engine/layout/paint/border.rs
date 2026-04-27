extern crate alloc;
use super::super::super::css::types::CssColor;
use super::super::types::LayoutBox;
use super::background::PaintCommand;
use alloc::vec::Vec;

pub fn paint_borders(layout_box: &LayoutBox) -> Vec<PaintCommand> {
    let mut commands = Vec::new();
    let d = &layout_box.dimensions;
    let color = layout_box.style.border_top_color.unwrap_or(CssColor::rgb(0, 0, 0));
    let bb = d.border_box();

    if d.border.top > 0.0 {
        commands.push(PaintCommand {
            x: bb.x,
            y: bb.y,
            width: bb.width,
            height: d.border.top,
            color,
        });
    }
    if d.border.bottom > 0.0 {
        commands.push(PaintCommand {
            x: bb.x,
            y: bb.y + bb.height - d.border.bottom,
            width: bb.width,
            height: d.border.bottom,
            color,
        });
    }
    if d.border.left > 0.0 {
        commands.push(PaintCommand {
            x: bb.x,
            y: bb.y,
            width: d.border.left,
            height: bb.height,
            color,
        });
    }
    if d.border.right > 0.0 {
        commands.push(PaintCommand {
            x: bb.x + bb.width - d.border.right,
            y: bb.y,
            width: d.border.right,
            height: bb.height,
            color,
        });
    }
    commands
}
