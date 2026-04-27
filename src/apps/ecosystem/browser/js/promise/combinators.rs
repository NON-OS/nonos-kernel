extern crate alloc;
use super::super::runtime::JsValue;
use super::state::{JsPromise, PromiseState};
use alloc::vec::Vec;

pub fn promise_resolve(value: JsValue) -> JsPromise {
    JsPromise::resolved(value)
}

pub fn promise_reject(reason: JsValue) -> JsPromise {
    JsPromise::rejected(reason)
}

pub fn promise_all(promises: &[JsPromise]) -> JsPromise {
    let result = JsPromise::new();

    if promises.is_empty() {
        result.resolve(JsValue::Array(alloc::rc::Rc::new(core::cell::RefCell::new(Vec::new()))));
        return result;
    }

    let mut values = Vec::with_capacity(promises.len());
    for promise in promises {
        let state = promise.state.borrow();
        match &*state {
            PromiseState::Fulfilled(v) => values.push(v.clone()),
            PromiseState::Rejected(r) => {
                result.reject(r.clone());
                return result;
            }
            PromiseState::Pending => {
                return result;
            }
        }
    }

    result.resolve(JsValue::Array(alloc::rc::Rc::new(core::cell::RefCell::new(values))));
    result
}

pub fn promise_race(promises: &[JsPromise]) -> JsPromise {
    let result = JsPromise::new();

    for promise in promises {
        let state = promise.state.borrow();
        match &*state {
            PromiseState::Fulfilled(v) => {
                result.resolve(v.clone());
                return result;
            }
            PromiseState::Rejected(r) => {
                result.reject(r.clone());
                return result;
            }
            PromiseState::Pending => continue,
        }
    }

    result
}
