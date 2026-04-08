#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::css::color::parse_color;
    use crate::apps::ecosystem::browser::engine::css::types::CssColor;

    #[test]
    fn test_parse_hex_3() {
        let c = parse_color("#f00").expect("should parse #f00");
        assert_eq!(c, CssColor::rgb(255, 0, 0));
    }

    #[test]
    fn test_parse_hex_6() {
        let c = parse_color("#00ff00").expect("should parse #00ff00");
        assert_eq!(c, CssColor::rgb(0, 255, 0));
    }

    #[test]
    fn test_parse_hex_8() {
        let c = parse_color("#ff000080").expect("should parse #ff000080");
        assert_eq!(c, CssColor::rgba(255, 0, 0, 128));
    }

    #[test]
    fn test_parse_rgb_function() {
        let c = parse_color("rgb(128, 64, 32)").expect("should parse rgb()");
        assert_eq!(c, CssColor::rgb(128, 64, 32));
    }

    #[test]
    fn test_parse_rgba_function() {
        let c = parse_color("rgba(255, 0, 0, 0.5)").expect("should parse rgba()");
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 0);
        assert_eq!(c.b, 0);
        assert_eq!(c.a, 127);
    }

    #[test]
    fn test_parse_named_color() {
        let c = parse_color("red").expect("should parse red");
        assert_eq!(c, CssColor::rgb(255, 0, 0));
    }

    #[test]
    fn test_parse_named_color_case_insensitive() {
        let c = parse_color("BLUE").expect("should parse BLUE");
        assert_eq!(c, CssColor::rgb(0, 0, 255));
    }

    #[test]
    fn test_parse_transparent() {
        let c = parse_color("transparent").expect("should parse transparent");
        assert_eq!(c, CssColor::rgba(0, 0, 0, 0));
    }

    #[test]
    fn test_parse_invalid_returns_none() {
        assert!(parse_color("notacolor").is_none());
    }

    #[test]
    fn test_color_to_u32() {
        let c = CssColor::rgb(255, 128, 0);
        let v = c.to_u32();
        assert_eq!(v >> 16 & 0xFF, 255);
        assert_eq!(v >> 8 & 0xFF, 128);
        assert_eq!(v & 0xFF, 0);
    }
}
