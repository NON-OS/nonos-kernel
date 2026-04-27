use super::block::layout_block;
use super::flex::layout_flex;
use super::position::{apply_relative_offset, sort_by_z_index};
use super::types::{BoxType, Dimensions, LayoutBox, Rect};

pub fn perform_layout(root: &mut LayoutBox, viewport_width: f32, viewport_height: f32) {
    let containing = Dimensions {
        content: Rect { x: 0.0, y: 0.0, width: viewport_width, height: viewport_height },
        ..Dimensions::default()
    };

    layout_recursive(root, &containing);
}

fn layout_recursive(layout_box: &mut LayoutBox, containing: &Dimensions) {
    match layout_box.box_type {
        BoxType::Block | BoxType::Anonymous | BoxType::InlineBlock => {
            layout_block(layout_box, containing);
        }
        BoxType::Flex => {
            layout_flex(layout_box, containing);
        }
        BoxType::Inline => {
            layout_block(layout_box, containing);
        }
    }

    apply_relative_offset(layout_box);

    for child in &mut layout_box.children {
        apply_relative_offset(child);
    }

    sort_by_z_index(&mut layout_box.children);
}
