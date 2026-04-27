use super::super::super::css::properties::AlignItems;
use super::super::types::LayoutBox;

pub fn align_cross_axis(parent: &mut LayoutBox, is_row: bool) {
    let cross_size = if is_row {
        parent.children.iter().map(|c| c.dimensions.margin_box().height).fold(0.0f32, |a, b| {
            if b > a {
                b
            } else {
                a
            }
        })
    } else {
        parent.dimensions.content.width
    };

    let align = parent.style.align_items;

    for child in &mut parent.children {
        let child_cross = if is_row {
            child.dimensions.margin_box().height
        } else {
            child.dimensions.margin_box().width
        };

        let offset = match align {
            AlignItems::FlexStart => 0.0,
            AlignItems::FlexEnd => cross_size - child_cross,
            AlignItems::Center => (cross_size - child_cross) / 2.0,
            AlignItems::Stretch => {
                if is_row {
                    child.dimensions.content.height =
                        cross_size - child.dimensions.total_vertical();
                } else {
                    child.dimensions.content.width =
                        cross_size - child.dimensions.total_horizontal();
                }
                0.0
            }
            AlignItems::Baseline => 0.0,
        };

        if is_row {
            child.dimensions.content.y += offset;
        } else {
            child.dimensions.content.x += offset;
        }
    }
}
