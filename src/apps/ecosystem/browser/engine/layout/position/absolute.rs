use super::super::super::css::cascade::resolve_length;
use super::super::super::css::properties::Position;
use super::super::super::css::types::CssValue;
use super::super::types::{Dimensions, LayoutBox};

pub fn layout_absolute(layout_box: &mut LayoutBox, containing: &Dimensions) {
    if layout_box.style.position != Position::Absolute {
        return;
    }

    let fs = 16.0;
    let vw = containing.content.width;
    let vh = containing.content.height;

    super::super::block::width::calculate_block_width(layout_box, containing.content.width);

    if !matches!(layout_box.style.top, CssValue::Auto) {
        let top = resolve_length(&layout_box.style.top, fs, vw, vh);
        layout_box.dimensions.content.y = containing.content.y
            + top
            + layout_box.dimensions.margin.top
            + layout_box.dimensions.border.top
            + layout_box.dimensions.padding.top;
    }

    if !matches!(layout_box.style.left, CssValue::Auto) {
        let left = resolve_length(&layout_box.style.left, fs, vw, vh);
        layout_box.dimensions.content.x = containing.content.x
            + left
            + layout_box.dimensions.margin.left
            + layout_box.dimensions.border.left
            + layout_box.dimensions.padding.left;
    }

    super::super::block::height::calculate_block_height(layout_box);
}
