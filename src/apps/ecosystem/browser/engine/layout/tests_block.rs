#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::layout::types::*;
    use crate::apps::ecosystem::browser::engine::layout::block::layout_block;
    use crate::apps::ecosystem::browser::engine::css::cascade::default_style;
    use crate::apps::ecosystem::browser::engine::css::types::{CssValue, Unit};
    use crate::apps::ecosystem::browser::engine::css::properties::Display;

    fn containing_800() -> Dimensions {
        Dimensions { content: Rect { x: 0.0, y: 0.0, width: 800.0, height: 0.0 }, ..Dimensions::default() }
    }

    fn block_box_with_width(width: f32) -> LayoutBox {
        let mut style = default_style();
        style.display = Display::Block;
        style.width = CssValue::Length(width, Unit::Px);
        LayoutBox::new_with_style(BoxType::Block, style)
    }

    #[test]
    fn test_block_fills_container_width() {
        let mut b = LayoutBox::new_with_style(BoxType::Block, default_style());
        layout_block(&mut b, &containing_800());
        assert!((b.dimensions.content.width - 800.0).abs() < 0.01);
    }

    #[test]
    fn test_block_explicit_width() {
        let mut b = block_box_with_width(400.0);
        layout_block(&mut b, &containing_800());
        assert!((b.dimensions.content.width - 400.0).abs() < 0.01);
    }

    #[test]
    fn test_blocks_stack_vertically() {
        let mut parent = LayoutBox::new_with_style(BoxType::Block, default_style());
        let child1 = block_box_with_width(800.0);
        let mut child2_style = default_style();
        child2_style.display = Display::Block;
        child2_style.height = CssValue::Length(50.0, Unit::Px);
        let child2 = LayoutBox::new_with_style(BoxType::Block, child2_style);
        parent.children.push(child1);
        parent.children.push(child2);
        layout_block(&mut parent, &containing_800());
        let y1 = parent.children[0].dimensions.content.y;
        let y2 = parent.children[1].dimensions.content.y;
        assert!(y2 > y1);
    }

    #[test]
    fn test_block_with_padding() {
        let mut style = default_style();
        style.display = Display::Block;
        style.padding_top = CssValue::Length(10.0, Unit::Px);
        style.padding_left = CssValue::Length(20.0, Unit::Px);
        let mut b = LayoutBox::new_with_style(BoxType::Block, style);
        layout_block(&mut b, &containing_800());
        assert!((b.dimensions.padding.top - 10.0).abs() < 0.01);
        assert!((b.dimensions.padding.left - 20.0).abs() < 0.01);
    }
}
