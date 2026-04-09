#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::string::String;
    use alloc::rc::Rc;
    use crate::apps::ecosystem::browser::js::prototype::chain::*;
    use crate::apps::ecosystem::browser::js::prototype::builtin_protos::BuiltinPrototypes;
    use crate::apps::ecosystem::browser::js::runtime::JsValue;

    #[test]
    fn test_own_property_lookup() {
        let obj = ProtoObject::new();
        ProtoChain::set_own_property(&obj, "x", JsValue::Number(42.0));
        let val = ProtoChain::get_property(&obj, "x");
        assert!(matches!(val, Some(JsValue::Number(n)) if (n - 42.0).abs() < 0.01));
    }

    #[test]
    fn test_proto_chain_lookup() {
        let parent = Rc::new(ProtoObject::new());
        ProtoChain::set_own_property(&parent, "inherited", JsValue::Bool(true));
        let child = ProtoObject::with_proto(parent);
        let val = ProtoChain::get_property(&child, "inherited");
        assert!(matches!(val, Some(JsValue::Bool(true))));
    }

    #[test]
    fn test_own_property_shadows_proto() {
        let parent = Rc::new(ProtoObject::new());
        ProtoChain::set_own_property(&parent, "x", JsValue::Number(1.0));
        let child = ProtoObject::with_proto(parent);
        ProtoChain::set_own_property(&child, "x", JsValue::Number(2.0));
        let val = ProtoChain::get_property(&child, "x");
        assert!(matches!(val, Some(JsValue::Number(n)) if (n - 2.0).abs() < 0.01));
    }

    #[test]
    fn test_has_own_property() {
        let obj = ProtoObject::new();
        ProtoChain::set_own_property(&obj, "a", JsValue::Null);
        assert!(ProtoChain::has_own_property(&obj, "a"));
        assert!(!ProtoChain::has_own_property(&obj, "b"));
    }

    #[test]
    fn test_chain_depth() {
        let a = Rc::new(ProtoObject::new());
        let b = Rc::new(ProtoObject::with_proto(a.clone()));
        let c = ProtoObject::with_proto(b);
        assert_eq!(ProtoChain::chain_depth(&c), 2);
    }

    #[test]
    fn test_builtin_prototypes_exist() {
        let protos = BuiltinPrototypes::new();
        assert!(ProtoChain::has_property(&protos.object_proto, "toString"));
        assert!(ProtoChain::has_property(&protos.object_proto, "hasOwnProperty"));
    }

    #[test]
    fn test_missing_property_returns_none() {
        let obj = ProtoObject::new();
        assert!(ProtoChain::get_property(&obj, "nonexistent").is_none());
    }
}
