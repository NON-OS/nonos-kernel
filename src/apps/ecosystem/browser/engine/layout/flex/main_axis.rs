use super::super::types::{LayoutBox, Dimensions};
use super::super::block::layout_block;
use super::super::super::css::properties::FlexDirection;
use super::super::super::css::cascade::resolve_length;
use super::cross_axis::align_cross_axis;
use super::wrap::distribute_and_position;

pub fn layout_flex(layout_box: &mut LayoutBox, containing: &Dimensions) {
    super::super::block::width::calculate_block_width(layout_box, containing.content.width);
    calculate_flex_position(layout_box, containing);

    let is_row = matches!(layout_box.style.flex_direction, FlexDirection::Row | FlexDirection::RowReverse);
    let main_size = if is_row { layout_box.dimensions.content.width } else { layout_box.dimensions.content.height };

    layout_flex_children(layout_box);
    distribute_and_position(layout_box, main_size, is_row);
    align_cross_axis(layout_box, is_row);
    calculate_flex_height(layout_box, is_row);
}

fn calculate_flex_position(layout_box: &mut LayoutBox, containing: &Dimensions) {
    let s = &layout_box.style;
    let fs = 16.0;
    let vw = containing.content.width;
    layout_box.dimensions.padding.top = resolve_length(&s.padding_top, fs, vw, 0.0);
    layout_box.dimensions.padding.bottom = resolve_length(&s.padding_bottom, fs, vw, 0.0);
    layout_box.dimensions.margin.top = resolve_length(&s.margin_top, fs, vw, 0.0);
    layout_box.dimensions.margin.bottom = resolve_length(&s.margin_bottom, fs, vw, 0.0);
    let margin_left = layout_box.dimensions.margin.left;
    let border_left = layout_box.dimensions.border.left;
    let padding_left = layout_box.dimensions.padding.left;
    let margin_top = layout_box.dimensions.margin.top;
    let border_top = layout_box.dimensions.border.top;
    let padding_top = layout_box.dimensions.padding.top;
    layout_box.dimensions.content.x = containing.content.x
        + margin_left + border_left + padding_left;
    layout_box.dimensions.content.y = containing.content.y + containing.content.height
        + margin_top + border_top + padding_top;
}

fn layout_flex_children(parent: &mut LayoutBox) {
    let containing = parent.dimensions;
    for child in &mut parent.children {
        layout_block(child, &containing);
    }
}

fn calculate_flex_height(layout_box: &mut LayoutBox, is_row: bool) {
    if is_row {
        let max_h = layout_box.children.iter()
            .map(|c| c.dimensions.margin_box().height)
            .fold(0.0f32, |a, b| if b > a { b } else { a });
        layout_box.dimensions.content.height = max_h;
    } else {
        layout_box.dimensions.content.height = layout_box.content_height();
    }
}
