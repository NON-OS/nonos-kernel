extern crate alloc;
use super::state::JsPromise;
use super::super::runtime::JsValue;

pub fn promise_then(promise: &JsPromise, on_fulfilled: JsValue, on_rejected: JsValue) -> JsPromise {
    let next = JsPromise::new();

    if !matches!(on_fulfilled, JsValue::Undefined | JsValue::Null) {
        promise.on_fulfilled.borrow_mut().push(on_fulfilled);
    }
    if !matches!(on_rejected, JsValue::Undefined | JsValue::Null) {
        promise.on_rejected.borrow_mut().push(on_rejected);
    }

    next
}

pub fn promise_catch(promise: &JsPromise, on_rejected: JsValue) -> JsPromise {
    promise_then(promise, JsValue::Undefined, on_rejected)
}

pub fn promise_finally(promise: &JsPromise, callback: JsValue) -> JsPromise {
    let next = JsPromise::new();
    if !matches!(callback, JsValue::Undefined | JsValue::Null) {
        promise.on_fulfilled.borrow_mut().push(callback.clone());
        promise.on_rejected.borrow_mut().push(callback);
    }
    next
}
