extern crate alloc;
use alloc::string::String;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use crate::apps::ecosystem::browser::js::runtime::JsValue;

pub fn create_navigator() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("userAgent"), JsValue::String(String::from("NONOS/0.8 (X11; NONOS x86_64)")));
    obj.insert(String::from("language"), JsValue::String(String::from("en-US")));
    obj.insert(String::from("languages"), JsValue::Array(alloc::rc::Rc::new(core::cell::RefCell::new(
        alloc::vec![JsValue::String(String::from("en-US")), JsValue::String(String::from("en"))]
    ))));
    obj.insert(String::from("onLine"), JsValue::Bool(true));
    obj.insert(String::from("cookieEnabled"), JsValue::Bool(true));
    obj.insert(String::from("platform"), JsValue::String(String::from("NONOS")));
    obj.insert(String::from("vendor"), JsValue::String(String::from("NONOS Contributors")));
    obj.insert(String::from("hardwareConcurrency"), JsValue::Number(1.0));
    obj.insert(String::from("maxTouchPoints"), JsValue::Number(0.0));
    obj.insert(String::from("doNotTrack"), JsValue::String(String::from("1")));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}
