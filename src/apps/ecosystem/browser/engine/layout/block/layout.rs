use super::super::types::{LayoutBox, BoxType, Dimensions};
use super::width::calculate_block_width;
use super::height::calculate_block_height;
use super::margin_collapse::collapse_margins;
use super::super::super::css::cascade::resolve_length;

pub fn layout_block(layout_box: &mut LayoutBox, containing: &Dimensions) {
    calculate_block_width(layout_box, containing.content.width);
    calculate_block_position(layout_box, containing);
    layout_block_children(layout_box);
    calculate_block_height(layout_box);
}

fn calculate_block_position(layout_box: &mut LayoutBox, containing: &Dimensions) {
    let style = &layout_box.style;
    let fs = 16.0;
    let vw = containing.content.width;

    layout_box.dimensions.padding.top = resolve_length(&style.padding_top, fs, vw, 0.0);
    layout_box.dimensions.padding.bottom = resolve_length(&style.padding_bottom, fs, vw, 0.0);
    layout_box.dimensions.border.top = resolve_length(&style.border_top_width, fs, vw, 0.0);
    layout_box.dimensions.border.bottom = resolve_length(&style.border_bottom_width, fs, vw, 0.0);
    layout_box.dimensions.margin.top = resolve_length(&style.margin_top, fs, vw, 0.0);
    layout_box.dimensions.margin.bottom = resolve_length(&style.margin_bottom, fs, vw, 0.0);

    let d = &layout_box.dimensions;
    layout_box.dimensions.content.x = containing.content.x
        + d.margin.left + d.border.left + d.padding.left;
    layout_box.dimensions.content.y = containing.content.y + containing.content.height
        + d.margin.top + d.border.top + d.padding.top;
}

fn layout_block_children(layout_box: &mut LayoutBox) {
    let mut child_y = 0.0f32;
    let mut prev_margin_bottom = 0.0f32;

    for child in &mut layout_box.children {
        let mut child_containing = layout_box.dimensions;
        child_containing.content.y = layout_box.dimensions.content.y + child_y;
        child_containing.content.height = 0.0;

        match child.box_type {
            BoxType::Block | BoxType::Anonymous => layout_block(child, &child_containing),
            BoxType::Flex => super::super::flex::layout_flex(child, &child_containing),
            _ => layout_block(child, &child_containing),
        }

        let collapsed = collapse_margins(prev_margin_bottom, child.dimensions.margin.top);
        let saved = child.dimensions.margin.top - collapsed;
        child.dimensions.content.y -= saved;

        let mb = child.dimensions.margin_box();
        child_y = mb.y + mb.height - layout_box.dimensions.content.y;
        prev_margin_bottom = child.dimensions.margin.bottom;
    }
}
