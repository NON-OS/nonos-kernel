extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use crate::apps::ecosystem::browser::js::runtime::JsValue;

pub fn create_history() -> JsValue {
    let mut obj = BTreeMap::new();
    let entries: Vec<JsValue> = Vec::new();
    obj.insert(String::from("_entries"), JsValue::Array(Rc::new(RefCell::new(entries))));
    obj.insert(String::from("_index"), JsValue::Number(0.0));
    obj.insert(String::from("length"), JsValue::Number(0.0));
    obj.insert(String::from("state"), JsValue::Null);
    obj.insert(String::from("pushState"), JsValue::NativeFunc(push_state));
    obj.insert(String::from("replaceState"), JsValue::NativeFunc(replace_state));
    obj.insert(String::from("back"), JsValue::NativeFunc(back));
    obj.insert(String::from("forward"), JsValue::NativeFunc(forward));
    obj.insert(String::from("go"), JsValue::NativeFunc(go));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn push_state(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Object(ref obj)) = args.first() {
        let state = args.get(1).cloned().unwrap_or(JsValue::Null);
        let _title = args.get(2).map(|v| v.to_string()).unwrap_or_default();
        let url = args.get(3).map(|v| v.to_string()).unwrap_or_default();
        let mut o = obj.borrow_mut();
        o.insert(String::from("state"), state);
        if let Some(JsValue::Array(ref entries)) = o.get("_entries") {
            entries.borrow_mut().push(JsValue::String(url));
        }
        let len = o.get("_entries").map(|e| if let JsValue::Array(ref a) = e { a.borrow().len() as f64 } else { 0.0 }).unwrap_or(0.0);
        o.insert(String::from("length"), JsValue::Number(len));
    }
    JsValue::Undefined
}

fn replace_state(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Object(ref obj)) = args.first() {
        let state = args.get(1).cloned().unwrap_or(JsValue::Null);
        obj.borrow_mut().insert(String::from("state"), state);
    }
    JsValue::Undefined
}

fn back(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn forward(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn go(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
