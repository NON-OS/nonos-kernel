extern crate alloc;
use alloc::string::String;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use crate::apps::ecosystem::browser::js::runtime::JsValue;

pub fn create_storage() -> JsValue {
    let mut obj = BTreeMap::new();
    let store: BTreeMap<String, JsValue> = BTreeMap::new();
    obj.insert(String::from("_store"), JsValue::Object(Rc::new(RefCell::new(store))));
    obj.insert(String::from("getItem"), JsValue::NativeFunc(get_item));
    obj.insert(String::from("setItem"), JsValue::NativeFunc(set_item));
    obj.insert(String::from("removeItem"), JsValue::NativeFunc(remove_item));
    obj.insert(String::from("clear"), JsValue::NativeFunc(clear));
    obj.insert(String::from("key"), JsValue::NativeFunc(key));
    obj.insert(String::from("length"), JsValue::Number(0.0));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn store_ref(args: &[JsValue]) -> Option<Rc<RefCell<BTreeMap<String, JsValue>>>> {
    if let Some(JsValue::Object(ref o)) = args.first() {
        if let Some(JsValue::Object(ref s)) = o.borrow().get("_store") { return Some(s.clone()); }
    }
    None
}

fn get_item(args: &[JsValue]) -> JsValue {
    let key = args.get(1).map(|v| v.to_string()).unwrap_or_default();
    store_ref(args).and_then(|s| s.borrow().get(&key).cloned()).unwrap_or(JsValue::Null)
}

fn set_item(args: &[JsValue]) -> JsValue {
    let key = args.get(1).map(|v| v.to_string()).unwrap_or_default();
    let val = args.get(2).map(|v| JsValue::String(v.to_string())).unwrap_or(JsValue::Undefined);
    if let Some(s) = store_ref(args) { s.borrow_mut().insert(key, val); }
    JsValue::Undefined
}

fn remove_item(args: &[JsValue]) -> JsValue {
    let key = args.get(1).map(|v| v.to_string()).unwrap_or_default();
    if let Some(s) = store_ref(args) { s.borrow_mut().remove(&key); }
    JsValue::Undefined
}

fn clear(args: &[JsValue]) -> JsValue {
    if let Some(s) = store_ref(args) { s.borrow_mut().clear(); }
    JsValue::Undefined
}

fn key(args: &[JsValue]) -> JsValue {
    let idx = args.get(1).map(|v| v.to_number() as usize).unwrap_or(0);
    if let Some(s) = store_ref(args) {
        let store = s.borrow();
        return store.keys().nth(idx).map(|k| JsValue::String(k.clone())).unwrap_or(JsValue::Null);
    }
    JsValue::Null
}
