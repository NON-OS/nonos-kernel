extern crate alloc;
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;

pub fn create_performance() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("now"), JsValue::NativeFunc(now));
    obj.insert(String::from("timeOrigin"), JsValue::Number(0.0));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn now(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
