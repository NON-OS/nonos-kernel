#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::css::parser::parse_inline_style;
    use crate::apps::ecosystem::browser::engine::css::parser::parse_stylesheet;
    use crate::apps::ecosystem::browser::engine::css::types::{CssValue, Unit};

    #[test]
    fn test_parse_single_rule() {
        let sheet = parse_stylesheet("div { color: red; }");
        assert_eq!(sheet.rules.len(), 1);
        assert!(!sheet.rules[0].declarations.is_empty());
    }

    #[test]
    fn test_parse_multiple_rules() {
        let sheet = parse_stylesheet("div { color: red; } p { margin: 10px; }");
        assert_eq!(sheet.rules.len(), 2);
    }

    #[test]
    fn test_parse_class_selector_rule() {
        let sheet = parse_stylesheet(".foo { display: block; }");
        assert_eq!(sheet.rules.len(), 1);
    }

    #[test]
    fn test_parse_inline_style_basic() {
        let decls = parse_inline_style("color: red; font-size: 16px");
        assert!(decls.len() >= 2);
    }

    #[test]
    fn test_parse_inline_style_dimension() {
        let decls = parse_inline_style("width: 200px");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].property, "width");
        match &decls[0].value {
            CssValue::Length(v, Unit::Px) => assert!((*v - 200.0).abs() < 0.01),
            _ => panic!("expected Length(200, Px)"),
        }
    }

    #[test]
    fn test_parse_media_query() {
        let sheet = parse_stylesheet("@media screen { div { color: blue; } }");
        assert_eq!(sheet.rules.len(), 1);
        assert!(sheet.rules[0].media_query.is_some());
    }

    #[test]
    fn test_parse_value_auto() {
        let decls = parse_inline_style("width: auto");
        assert_eq!(decls.len(), 1);
        assert!(decls[0].value.is_auto());
    }

    #[test]
    fn test_parse_value_percentage() {
        let decls = parse_inline_style("width: 50%");
        match &decls[0].value {
            CssValue::Percentage(v) => assert!((*v - 50.0).abs() < 0.01),
            _ => panic!("expected Percentage(50)"),
        }
    }
}
