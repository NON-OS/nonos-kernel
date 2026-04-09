#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::js::security::*;

    #[test]
    fn test_same_origin_match() {
        let a = Origin::from_url("https://example.com/page");
        let b = Origin::from_url("https://example.com/other");
        assert!(a.same_origin(&b));
    }

    #[test]
    fn test_different_scheme_not_same_origin() {
        let a = Origin::from_url("https://example.com");
        let b = Origin::from_url("http://example.com");
        assert!(!a.same_origin(&b));
    }

    #[test]
    fn test_different_port_not_same_origin() {
        let a = Origin::from_url("https://example.com:443");
        let b = Origin::from_url("https://example.com:8080");
        assert!(!a.same_origin(&b));
    }

    #[test]
    fn test_default_port_matches() {
        let a = Origin::from_url("https://example.com");
        let b = Origin::from_url("https://example.com:443");
        assert!(a.same_origin(&b));
    }

    #[test]
    fn test_sop_blocks_cross_origin() {
        assert_eq!(same_origin_check("https://evil.com/x", "https://example.com/y"), SopDecision::Block);
    }

    #[test]
    fn test_sop_allows_same_origin() {
        assert_eq!(same_origin_check("https://example.com/a", "https://example.com/b"), SopDecision::Allow);
    }

    #[test]
    fn test_cors_wildcard_allows() {
        let req = CorsRequest { origin: Origin::from_url("https://other.com"), method: alloc::string::String::from("GET"), headers: alloc::vec![] };
        assert_eq!(cors_check(&req, Some("*"), None, None), CorsResult::Allowed);
    }

    #[test]
    fn test_cors_no_header_blocks() {
        let req = CorsRequest { origin: Origin::from_url("https://other.com"), method: alloc::string::String::from("GET"), headers: alloc::vec![] };
        assert_eq!(cors_check(&req, None, None, None), CorsResult::Blocked);
    }

    #[test]
    fn test_cors_exact_match_allows() {
        let req = CorsRequest { origin: Origin::from_url("https://app.com"), method: alloc::string::String::from("GET"), headers: alloc::vec![] };
        assert_eq!(cors_check(&req, Some("https://app.com"), None, None), CorsResult::Allowed);
    }

    #[test]
    fn test_csp_self_allows_same_origin() {
        let policy = CspPolicy::parse("script-src 'self'", false);
        assert!(csp_allows(&policy, "script-src", "https://example.com/app.js", "https://example.com"));
    }

    #[test]
    fn test_csp_self_blocks_cross_origin() {
        let policy = CspPolicy::parse("script-src 'self'", false);
        assert!(!csp_allows(&policy, "script-src", "https://evil.com/bad.js", "https://example.com"));
    }

    #[test]
    fn test_csp_none_blocks_all() {
        let policy = CspPolicy::parse("script-src 'none'", false);
        assert!(!csp_allows(&policy, "script-src", "https://example.com/x.js", "https://example.com"));
    }

    #[test]
    fn test_mixed_content_blocks() {
        assert!(block_mixed_content("https://example.com", "http://cdn.example.com/img.png"));
    }

    #[test]
    fn test_mixed_content_allows_secure() {
        assert!(!block_mixed_content("https://example.com", "https://cdn.example.com/img.png"));
    }
}
