use super::types::{LayoutBox, BoxType, Dimensions};
use super::super::css::cascade::default_style;

impl LayoutBox {
    pub fn new(box_type: BoxType) -> Self {
        Self {
            box_type,
            dimensions: Dimensions::default(),
            children: alloc::vec::Vec::new(),
            style: default_style(),
            node_index: None,
        }
    }

    pub fn new_with_style(box_type: BoxType, style: super::super::css::cascade::ComputedStyle) -> Self {
        Self {
            box_type,
            dimensions: Dimensions::default(),
            children: alloc::vec::Vec::new(),
            style,
            node_index: None,
        }
    }

    pub fn anonymous_block() -> Self {
        Self::new(BoxType::Anonymous)
    }

    pub fn content_height(&self) -> f32 {
        self.children.iter().fold(0.0, |acc, child| {
            let mb = child.dimensions.margin_box();
            let child_bottom = mb.y + mb.height - self.dimensions.content.y;
            if child_bottom > acc { child_bottom } else { acc }
        })
    }
}
