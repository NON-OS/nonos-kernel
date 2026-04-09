#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::js::promise::*;
    use crate::apps::ecosystem::browser::js::runtime::JsValue;

    #[test]
    fn test_promise_starts_pending() {
        let p = JsPromise::new();
        assert!(p.is_pending());
    }

    #[test]
    fn test_promise_resolve() {
        let p = JsPromise::new();
        p.resolve(JsValue::Number(42.0));
        assert!(p.is_settled());
        assert!(matches!(*p.state.borrow(), PromiseState::Fulfilled(_)));
    }

    #[test]
    fn test_promise_reject() {
        let p = JsPromise::new();
        p.reject(JsValue::String(alloc::string::String::from("err")));
        assert!(matches!(*p.state.borrow(), PromiseState::Rejected(_)));
    }

    #[test]
    fn test_promise_resolve_only_once() {
        let p = JsPromise::new();
        p.resolve(JsValue::Number(1.0));
        p.resolve(JsValue::Number(2.0));
        if let PromiseState::Fulfilled(JsValue::Number(n)) = &*p.state.borrow() {
            assert!((*n - 1.0).abs() < 0.01);
        }
    }

    #[test]
    fn test_promise_resolve_shorthand() {
        let p = promise_resolve(JsValue::Bool(true));
        assert!(matches!(*p.state.borrow(), PromiseState::Fulfilled(JsValue::Bool(true))));
    }

    #[test]
    fn test_promise_reject_shorthand() {
        let p = promise_reject(JsValue::Null);
        assert!(matches!(*p.state.borrow(), PromiseState::Rejected(JsValue::Null)));
    }

    #[test]
    fn test_promise_all_empty() {
        let p = promise_all(&[]);
        assert!(p.is_settled());
    }

    #[test]
    fn test_promise_all_fulfilled() {
        let a = JsPromise::resolved(JsValue::Number(1.0));
        let b = JsPromise::resolved(JsValue::Number(2.0));
        let result = promise_all(&[a, b]);
        assert!(result.is_settled());
    }

    #[test]
    fn test_promise_race_first_wins() {
        let a = JsPromise::resolved(JsValue::Number(1.0));
        let b = JsPromise::new();
        let result = promise_race(&[a, b]);
        assert!(result.is_settled());
    }
}
