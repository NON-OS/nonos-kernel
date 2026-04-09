extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use crate::apps::ecosystem::browser::js::runtime::JsValue;

pub fn create_headers(pairs: &[(String, String)]) -> JsValue {
    let mut obj = BTreeMap::new();
    let mut store = BTreeMap::new();
    for (k, v) in pairs { store.insert(k.clone(), JsValue::String(v.clone())); }
    obj.insert(String::from("_store"), JsValue::Object(Rc::new(RefCell::new(store))));
    obj.insert(String::from("get"), JsValue::NativeFunc(get));
    obj.insert(String::from("set"), JsValue::NativeFunc(set));
    obj.insert(String::from("has"), JsValue::NativeFunc(has));
    obj.insert(String::from("delete"), JsValue::NativeFunc(delete));
    obj.insert(String::from("entries"), JsValue::NativeFunc(entries));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn store_ref(args: &[JsValue]) -> Option<Rc<RefCell<BTreeMap<String, JsValue>>>> {
    if let Some(JsValue::Object(ref obj)) = args.first() {
        if let Some(JsValue::Object(ref s)) = obj.borrow().get("_store") {
            return Some(s.clone());
        }
    }
    None
}

fn get(args: &[JsValue]) -> JsValue {
    let key = args.get(1).map(|v| v.to_string()).unwrap_or_default();
    store_ref(args).and_then(|s| s.borrow().get(&key).cloned()).unwrap_or(JsValue::Null)
}

fn set(args: &[JsValue]) -> JsValue {
    let key = args.get(1).map(|v| v.to_string()).unwrap_or_default();
    let val = args.get(2).cloned().unwrap_or(JsValue::Undefined);
    if let Some(s) = store_ref(args) { s.borrow_mut().insert(key, val); }
    JsValue::Undefined
}

fn has(args: &[JsValue]) -> JsValue {
    let key = args.get(1).map(|v| v.to_string()).unwrap_or_default();
    JsValue::Bool(store_ref(args).map(|s| s.borrow().contains_key(&key)).unwrap_or(false))
}

fn delete(args: &[JsValue]) -> JsValue {
    let key = args.get(1).map(|v| v.to_string()).unwrap_or_default();
    if let Some(s) = store_ref(args) { s.borrow_mut().remove(&key); }
    JsValue::Undefined
}

fn entries(args: &[JsValue]) -> JsValue {
    if let Some(s) = store_ref(args) {
        let items: Vec<JsValue> = s.borrow().iter().map(|(k, v)| {
            JsValue::Array(Rc::new(RefCell::new(alloc::vec![JsValue::String(k.clone()), v.clone()])))
        }).collect();
        return JsValue::Array(Rc::new(RefCell::new(items)));
    }
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
