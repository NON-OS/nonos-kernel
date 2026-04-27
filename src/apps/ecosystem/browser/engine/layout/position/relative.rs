use super::super::super::css::cascade::resolve_length;
use super::super::super::css::properties::Position;
use super::super::types::LayoutBox;

pub fn apply_relative_offset(layout_box: &mut LayoutBox) {
    if layout_box.style.position != Position::Relative {
        return;
    }

    let fs = 16.0;
    let vw = layout_box.dimensions.content.width;

    let top = resolve_length(&layout_box.style.top, fs, vw, 0.0);
    let left = resolve_length(&layout_box.style.left, fs, vw, 0.0);

    layout_box.dimensions.content.x += left;
    layout_box.dimensions.content.y += top;
}
