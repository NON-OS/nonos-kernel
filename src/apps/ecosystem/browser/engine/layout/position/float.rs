use super::super::types::LayoutBox;
use super::super::super::css::properties::{Float, Clear};

pub fn apply_float(layout_box: &mut LayoutBox, _container_width: f32, float_left_x: &mut f32, float_right_x: &mut f32) {
    match layout_box.style.float {
        Float::Left => {
            layout_box.dimensions.content.x = *float_left_x
                + layout_box.dimensions.margin.left
                + layout_box.dimensions.border.left
                + layout_box.dimensions.padding.left;
            *float_left_x += layout_box.dimensions.margin_box().width;
        }
        Float::Right => {
            let box_width = layout_box.dimensions.margin_box().width;
            *float_right_x -= box_width;
            layout_box.dimensions.content.x = *float_right_x
                + layout_box.dimensions.margin.left
                + layout_box.dimensions.border.left
                + layout_box.dimensions.padding.left;
        }
        Float::None => {}
    }
}

pub fn apply_clear(clear: Clear, float_left_bottom: f32, float_right_bottom: f32) -> f32 {
    match clear {
        Clear::Left => float_left_bottom,
        Clear::Right => float_right_bottom,
        Clear::Both => {
            if float_left_bottom > float_right_bottom { float_left_bottom }
            else { float_right_bottom }
        }
        Clear::None => 0.0,
    }
}
