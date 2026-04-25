extern crate alloc;
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

pub fn create_crypto() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("getRandomValues"), JsValue::NativeFunc(get_random_values));
    let mut subtle = BTreeMap::new();
    subtle.insert(String::from("digest"), JsValue::NativeFunc(subtle_digest));
    obj.insert(String::from("subtle"), JsValue::Object(Rc::new(RefCell::new(subtle))));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn get_random_values(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Array(ref arr)) = args.get(1) {
        let mut rng = simple_rng();
        let mut out = arr.borrow_mut();
        for val in out.iter_mut() {
            *val = JsValue::Number((rng() % 256) as f64);
        }
    }
    args.get(1).cloned().unwrap_or(JsValue::Undefined)
}

fn subtle_digest(_args: &[JsValue]) -> JsValue {
    JsValue::Promise(crate::apps::ecosystem::browser::js::promise::promise_resolve(JsValue::Array(
        Rc::new(RefCell::new(Vec::new())),
    )))
}

fn simple_rng() -> impl FnMut() -> u64 {
    let mut state: u64 = 0x5DEE_CE66_D47F_F971;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}
