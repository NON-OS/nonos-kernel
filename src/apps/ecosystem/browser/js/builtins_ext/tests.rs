#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::js::builtins_ext::*;
    use crate::apps::ecosystem::browser::js::runtime::JsValue;

    #[test]
    fn test_js_error_display() {
        let err = JsError::type_error("not a function");
        assert_eq!(alloc::format!("{}", err), "TypeError: not a function");
    }

    #[test]
    fn test_js_error_kind_name() {
        assert_eq!(JsError::reference_error("x").name(), "ReferenceError");
        assert_eq!(JsError::range_error("oob").name(), "RangeError");
        assert_eq!(JsError::syntax_error("bad").name(), "SyntaxError");
    }

    #[test]
    fn test_map_set_get() {
        let mut m = JsMap::new();
        m.set("key", JsValue::Number(99.0));
        let val = m.get("key");
        assert!(matches!(val, JsValue::Number(n) if (n - 99.0).abs() < 0.01));
    }

    #[test]
    fn test_map_has_delete() {
        let mut m = JsMap::new();
        m.set("a", JsValue::Null);
        assert!(m.has("a"));
        m.delete("a");
        assert!(!m.has("a"));
    }

    #[test]
    fn test_map_size() {
        let mut m = JsMap::new();
        m.set("x", JsValue::Null);
        m.set("y", JsValue::Null);
        assert_eq!(m.size(), 2);
        m.clear();
        assert_eq!(m.size(), 0);
    }

    #[test]
    fn test_set_add_has() {
        let mut s = JsSet::new();
        s.add("hello");
        assert!(s.has("hello"));
        assert!(!s.has("world"));
    }

    #[test]
    fn test_set_no_duplicates() {
        let mut s = JsSet::new();
        s.add("x");
        s.add("x");
        assert_eq!(s.size(), 1);
    }

    #[test]
    fn test_symbol_unique() {
        let a = JsSymbol::new();
        let b = JsSymbol::new();
        assert_ne!(a, b);
    }

    #[test]
    fn test_symbol_iterator() {
        let s = JsSymbol::iterator();
        assert!(s.is_iterator());
    }

    #[test]
    fn test_symbol_registry() {
        let mut reg = SymbolRegistry::new();
        let s1 = reg.symbol_for("shared");
        let s2 = reg.symbol_for("shared");
        assert_eq!(s1, s2);
        assert_eq!(reg.key_for(s1), Some("shared"));
    }
}
