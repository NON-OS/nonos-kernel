use super::super::super::css::properties::JustifyContent;
use super::super::types::LayoutBox;

pub fn distribute_and_position(parent: &mut LayoutBox, main_size: f32, is_row: bool) {
    grow_children(parent, main_size, is_row);
    position_children(parent, main_size, is_row);
}

fn grow_children(parent: &mut LayoutBox, main_size: f32, is_row: bool) {
    let total_child: f32 = parent
        .children
        .iter()
        .map(|c| {
            if is_row {
                c.dimensions.margin_box().width
            } else {
                c.dimensions.margin_box().height
            }
        })
        .sum();
    let free = main_size - total_child;
    let total_grow: f32 = parent.children.iter().map(|c| c.style.flex_grow).sum();

    if free > 0.0 && total_grow > 0.0 {
        for child in &mut parent.children {
            let share = (child.style.flex_grow / total_grow) * free;
            if is_row {
                child.dimensions.content.width += share;
            } else {
                child.dimensions.content.height += share;
            }
        }
    }
}

fn position_children(parent: &mut LayoutBox, main_size: f32, is_row: bool) {
    let total: f32 = parent
        .children
        .iter()
        .map(|c| {
            if is_row {
                c.dimensions.margin_box().width
            } else {
                c.dimensions.margin_box().height
            }
        })
        .sum();
    let free = (main_size - total).max(0.0);
    let count = parent.children.len();
    let (initial, gap) = justify_offsets(parent.style.justify_content, free, count);
    let mut offset = initial;

    for child in &mut parent.children {
        if is_row {
            child.dimensions.content.x = parent.dimensions.content.x
                + offset
                + child.dimensions.margin.left
                + child.dimensions.border.left
                + child.dimensions.padding.left;
            offset += child.dimensions.margin_box().width + gap;
        } else {
            child.dimensions.content.y = parent.dimensions.content.y
                + offset
                + child.dimensions.margin.top
                + child.dimensions.border.top
                + child.dimensions.padding.top;
            offset += child.dimensions.margin_box().height + gap;
        }
    }
}

fn justify_offsets(justify: JustifyContent, free: f32, count: usize) -> (f32, f32) {
    match justify {
        JustifyContent::FlexStart => (0.0, 0.0),
        JustifyContent::FlexEnd => (free, 0.0),
        JustifyContent::Center => (free / 2.0, 0.0),
        JustifyContent::SpaceBetween if count > 1 => (0.0, free / (count - 1) as f32),
        JustifyContent::SpaceAround if count > 0 => {
            let g = free / count as f32;
            (g / 2.0, g)
        }
        JustifyContent::SpaceEvenly if count > 0 => {
            let g = free / (count + 1) as f32;
            (g, g)
        }
        _ => (0.0, 0.0),
    }
}
