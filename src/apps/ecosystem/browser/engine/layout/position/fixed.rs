use super::super::super::css::properties::Position;
use super::super::types::{Dimensions, LayoutBox, Rect};
use super::absolute::layout_absolute;

pub fn layout_fixed(layout_box: &mut LayoutBox, viewport_width: f32, viewport_height: f32) {
    if layout_box.style.position != Position::Fixed {
        return;
    }

    let viewport = Dimensions {
        content: Rect { x: 0.0, y: 0.0, width: viewport_width, height: viewport_height },
        ..Dimensions::default()
    };

    layout_absolute(layout_box, &viewport);
}
