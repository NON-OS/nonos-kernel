#[cfg(test)]
mod tests {
    use super::super::scan::tokenize;
    use super::super::token_types::CssToken;

    #[test]
    fn test_tokenize_simple_rule() {
        let tokens = tokenize("div { color: red; }");
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Ident(s) if s == "div")));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::OpenBrace)));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Ident(s) if s == "color")));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Colon)));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Ident(s) if s == "red")));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Semicolon)));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::CloseBrace)));
    }

    #[test]
    fn test_tokenize_class_selector() {
        let tokens = tokenize(".foo { }");
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Dot)));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Ident(s) if s == "foo")));
    }

    #[test]
    fn test_tokenize_id_selector() {
        let tokens = tokenize("#bar { }");
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Hash(s) if s == "bar")));
    }

    #[test]
    fn test_tokenize_dimension() {
        let tokens = tokenize("width: 100px;");
        assert!(tokens.iter().any(
            |t| matches!(t, CssToken::Dimension(v, u) if (*v - 100.0).abs() < 0.01 && u == "px")
        ));
    }

    #[test]
    fn test_tokenize_percentage() {
        let tokens = tokenize("width: 50%;");
        assert!(tokens
            .iter()
            .any(|t| matches!(t, CssToken::Percentage(v) if (*v - 50.0).abs() < 0.01)));
    }

    #[test]
    fn test_tokenize_string() {
        let tokens = tokenize("content: \"hello\";");
        assert!(tokens.iter().any(|t| matches!(t, CssToken::String(s) if s == "hello")));
    }

    #[test]
    fn test_tokenize_comment_skipped() {
        let tokens = tokenize("/* comment */ div { }");
        assert!(!tokens.iter().any(|t| matches!(t, CssToken::Ident(s) if s == "comment")));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Ident(s) if s == "div")));
    }

    #[test]
    fn test_tokenize_combinators() {
        let tokens = tokenize("div > .foo + span ~ p { }");
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Greater)));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Plus)));
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Tilde)));
    }

    #[test]
    fn test_tokenize_at_keyword() {
        let tokens = tokenize("@media screen { }");
        assert!(tokens.iter().any(|t| matches!(t, CssToken::AtKeyword(s) if s == "media")));
    }

    #[test]
    fn test_tokenize_function() {
        let tokens = tokenize("rgb(255, 0, 0)");
        assert!(tokens.iter().any(|t| matches!(t, CssToken::Function(s) if s == "rgb")));
    }
}
