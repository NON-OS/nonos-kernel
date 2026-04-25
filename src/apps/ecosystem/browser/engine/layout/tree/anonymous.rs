extern crate alloc;
use super::super::types::{BoxType, LayoutBox};
use alloc::vec::Vec;

pub fn wrap_anonymous_blocks(parent: &mut LayoutBox) {
    if !has_mixed_children(parent) {
        return;
    }

    let children = core::mem::take(&mut parent.children);
    let mut result: Vec<LayoutBox> = Vec::new();
    let mut inline_group: Vec<LayoutBox> = Vec::new();

    for child in children {
        if is_block_level(&child) {
            if !inline_group.is_empty() {
                let mut anon = LayoutBox::anonymous_block();
                anon.children = core::mem::take(&mut inline_group);
                result.push(anon);
            }
            result.push(child);
        } else {
            inline_group.push(child);
        }
    }

    if !inline_group.is_empty() {
        let mut anon = LayoutBox::anonymous_block();
        anon.children = inline_group;
        result.push(anon);
    }

    parent.children = result;
}

fn has_mixed_children(parent: &LayoutBox) -> bool {
    let mut has_block = false;
    let mut has_inline = false;
    for child in &parent.children {
        if is_block_level(child) {
            has_block = true;
        } else {
            has_inline = true;
        }
    }
    has_block && has_inline
}

fn is_block_level(layout_box: &LayoutBox) -> bool {
    matches!(layout_box.box_type, BoxType::Block | BoxType::Flex | BoxType::Anonymous)
}
