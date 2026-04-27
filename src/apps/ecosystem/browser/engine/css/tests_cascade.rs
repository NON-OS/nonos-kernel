#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::css::cascade::*;
    use crate::apps::ecosystem::browser::engine::css::properties::*;
    use crate::apps::ecosystem::browser::engine::css::types::*;

    #[test]
    fn test_default_style_values() {
        let style = default_style();
        assert_eq!(style.display, Display::Inline);
        assert_eq!(style.position, Position::Static);
        assert!(style.width.is_auto());
        assert!(style.height.is_auto());
        assert!((style.opacity - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_display_from_str() {
        assert_eq!(Display::from_str("block"), Display::Block);
        assert_eq!(Display::from_str("flex"), Display::Flex);
        assert_eq!(Display::from_str("none"), Display::None);
        assert_eq!(Display::from_str("inline-block"), Display::InlineBlock);
    }

    #[test]
    fn test_position_from_str() {
        assert_eq!(Position::from_str("absolute"), Position::Absolute);
        assert_eq!(Position::from_str("relative"), Position::Relative);
        assert_eq!(Position::from_str("fixed"), Position::Fixed);
    }

    #[test]
    fn test_font_weight_is_bold() {
        assert!(FontWeight::Bold.is_bold());
        assert!(FontWeight::W700.is_bold());
        assert!(!FontWeight::Normal.is_bold());
        assert!(!FontWeight::W400.is_bold());
    }

    #[test]
    fn test_resolve_length_px() {
        let val = CssValue::Length(20.0, Unit::Px);
        let resolved = resolve_length(&val, 16.0, 1920.0, 1080.0);
        assert!((resolved - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_resolve_length_em() {
        let val = CssValue::Length(2.0, Unit::Em);
        let resolved = resolve_length(&val, 16.0, 1920.0, 1080.0);
        assert!((resolved - 32.0).abs() < 0.01);
    }

    #[test]
    fn test_resolve_length_vw() {
        let val = CssValue::Length(50.0, Unit::Vw);
        let resolved = resolve_length(&val, 16.0, 1920.0, 1080.0);
        assert!((resolved - 960.0).abs() < 0.01);
    }

    #[test]
    fn test_flex_direction_from_str() {
        assert_eq!(FlexDirection::from_str("row"), FlexDirection::Row);
        assert_eq!(FlexDirection::from_str("column"), FlexDirection::Column);
        assert_eq!(FlexDirection::from_str("row-reverse"), FlexDirection::RowReverse);
    }

    #[test]
    fn test_justify_content_from_str() {
        assert_eq!(JustifyContent::from_str("center"), JustifyContent::Center);
        assert_eq!(JustifyContent::from_str("space-between"), JustifyContent::SpaceBetween);
    }

    #[test]
    fn test_text_align_from_str() {
        assert_eq!(TextAlign::from_str("center"), TextAlign::Center);
        assert_eq!(TextAlign::from_str("right"), TextAlign::Right);
        assert_eq!(TextAlign::from_str("justify"), TextAlign::Justify);
    }
}
