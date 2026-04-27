extern crate alloc;
use super::super::super::css::cascade::ComputedStyle;
use super::super::super::css::properties::Display;
use super::super::super::types::Node;
use super::super::types::{BoxType, LayoutBox};
use super::anonymous::wrap_anonymous_blocks;

pub fn build_layout_tree(
    node: &Node,
    styles: &[ComputedStyle],
    index: &mut u32,
) -> Option<LayoutBox> {
    let current_index = *index;
    *index += 1;

    let style = styles
        .get(current_index as usize)
        .cloned()
        .unwrap_or_else(super::super::super::css::cascade::default_style);

    if style.display == Display::None {
        skip_children(node, index);
        return None;
    }

    let box_type = box_type_from_display(&style);
    let mut layout_box = LayoutBox::new_with_style(box_type, style);
    layout_box.node_index = Some(current_index);

    for child in &node.children {
        if let Some(child_box) = build_layout_tree(child, styles, index) {
            layout_box.children.push(child_box);
        }
    }

    if box_type == BoxType::Block || box_type == BoxType::Flex {
        wrap_anonymous_blocks(&mut layout_box);
    }

    Some(layout_box)
}

fn box_type_from_display(style: &ComputedStyle) -> BoxType {
    match style.display {
        Display::Block | Display::Grid | Display::ListItem | Display::Table => BoxType::Block,
        Display::Flex => BoxType::Flex,
        Display::InlineBlock => BoxType::InlineBlock,
        _ => BoxType::Inline,
    }
}

fn skip_children(node: &Node, index: &mut u32) {
    for child in &node.children {
        *index += 1;
        skip_children(child, index);
    }
}
