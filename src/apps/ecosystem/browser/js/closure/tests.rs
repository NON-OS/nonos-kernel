#[cfg(test)]
mod tests {
    extern crate alloc;
    use crate::apps::ecosystem::browser::js::closure::binding::*;
    use crate::apps::ecosystem::browser::js::closure::scope_chain::*;
    use crate::apps::ecosystem::browser::js::closure::this_binding::*;
    use crate::apps::ecosystem::browser::js::runtime::JsValue;
    use alloc::string::String;

    #[test]
    fn test_scope_declare_and_lookup() {
        let scope = LexicalScope::new();
        ScopeChain::declare(&scope, String::from("x"), JsValue::Number(10.0));
        let val = ScopeChain::lookup(&scope, "x");
        assert!(matches!(val, Some(JsValue::Number(n)) if (n - 10.0).abs() < 0.01));
    }

    #[test]
    fn test_child_scope_sees_parent() {
        let parent = LexicalScope::new();
        ScopeChain::declare(&parent, String::from("y"), JsValue::Bool(true));
        let child = LexicalScope::child(parent);
        assert!(matches!(ScopeChain::lookup(&child, "y"), Some(JsValue::Bool(true))));
    }

    #[test]
    fn test_child_shadows_parent() {
        let parent = LexicalScope::new();
        ScopeChain::declare(&parent, String::from("z"), JsValue::Number(1.0));
        let child = LexicalScope::child(parent);
        ScopeChain::declare(&child, String::from("z"), JsValue::Number(2.0));
        let val = ScopeChain::lookup(&child, "z");
        assert!(matches!(val, Some(JsValue::Number(n)) if (n - 2.0).abs() < 0.01));
    }

    #[test]
    fn test_assign_updates_existing() {
        let scope = LexicalScope::new();
        ScopeChain::declare(&scope, String::from("a"), JsValue::Number(0.0));
        ScopeChain::assign(&scope, "a", JsValue::Number(99.0));
        let val = ScopeChain::lookup(&scope, "a");
        assert!(matches!(val, Some(JsValue::Number(n)) if (n - 99.0).abs() < 0.01));
    }

    #[test]
    fn test_scope_depth() {
        let a = LexicalScope::new();
        let b = LexicalScope::child(a);
        let c = LexicalScope::child(b);
        assert_eq!(ScopeChain::depth(&c), 2);
    }

    #[test]
    fn test_this_binding_global() {
        let binding = ThisBinding::Global;
        let resolved = resolve_this(&binding, &JsValue::Undefined);
        assert!(matches!(resolved, JsValue::Undefined));
    }

    #[test]
    fn test_this_binding_bound() {
        let binding = bind_explicit_this(JsValue::Number(42.0));
        let resolved = resolve_this(&binding, &JsValue::Undefined);
        assert!(matches!(resolved, JsValue::Number(n) if (n - 42.0).abs() < 0.01));
    }

    #[test]
    fn test_this_binding_arrow_inherits() {
        let enclosing = JsValue::String(alloc::string::String::from("outer"));
        let binding = arrow_this();
        let resolved = resolve_this(&binding, &enclosing);
        assert!(matches!(resolved, JsValue::String(ref s) if s == "outer"));
    }
}
