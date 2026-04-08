#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::layout::types::*;
    use crate::apps::ecosystem::browser::engine::layout::flex::layout_flex;
    use crate::apps::ecosystem::browser::engine::css::cascade::default_style;
    use crate::apps::ecosystem::browser::engine::css::types::{CssValue, Unit};
    use crate::apps::ecosystem::browser::engine::css::properties::*;

    fn containing_600() -> Dimensions {
        Dimensions { content: Rect { x: 0.0, y: 0.0, width: 600.0, height: 0.0 }, ..Dimensions::default() }
    }

    fn flex_container() -> LayoutBox {
        let mut style = default_style();
        style.display = Display::Flex;
        style.flex_direction = FlexDirection::Row;
        LayoutBox::new_with_style(BoxType::Flex, style)
    }

    fn flex_child(width: f32) -> LayoutBox {
        let mut style = default_style();
        style.display = Display::Block;
        style.width = CssValue::Length(width, Unit::Px);
        style.height = CssValue::Length(50.0, Unit::Px);
        LayoutBox::new_with_style(BoxType::Block, style)
    }

    #[test]
    fn test_flex_row_children_horizontal() {
        let mut parent = flex_container();
        parent.children.push(flex_child(100.0));
        parent.children.push(flex_child(100.0));
        layout_flex(&mut parent, &containing_600());
        let x1 = parent.children[0].dimensions.content.x;
        let x2 = parent.children[1].dimensions.content.x;
        assert!(x2 > x1);
    }

    #[test]
    fn test_flex_grow_distributes_space() {
        let mut parent = flex_container();
        let mut c1 = flex_child(100.0);
        c1.style.flex_grow = 1.0;
        let mut c2 = flex_child(100.0);
        c2.style.flex_grow = 1.0;
        parent.children.push(c1);
        parent.children.push(c2);
        layout_flex(&mut parent, &containing_600());
        let w1 = parent.children[0].dimensions.content.width;
        let w2 = parent.children[1].dimensions.content.width;
        assert!((w1 - w2).abs() < 1.0);
        assert!(w1 > 100.0);
    }

    #[test]
    fn test_flex_justify_center() {
        let mut parent = flex_container();
        parent.style.justify_content = JustifyContent::Center;
        parent.children.push(flex_child(100.0));
        layout_flex(&mut parent, &containing_600());
        let x = parent.children[0].dimensions.content.x;
        assert!(x > 200.0);
    }
}
