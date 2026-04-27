extern crate alloc;
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

pub fn create_form_data() -> JsValue {
    let mut obj = BTreeMap::new();
    let store: BTreeMap<String, JsValue> = BTreeMap::new();
    obj.insert(String::from("_store"), JsValue::Object(Rc::new(RefCell::new(store))));
    obj.insert(String::from("append"), JsValue::NativeFunc(append));
    obj.insert(String::from("get"), JsValue::NativeFunc(get));
    obj.insert(String::from("getAll"), JsValue::NativeFunc(get_all));
    obj.insert(String::from("has"), JsValue::NativeFunc(has));
    obj.insert(String::from("delete"), JsValue::NativeFunc(delete));
    obj.insert(String::from("entries"), JsValue::NativeFunc(entries));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn store_ref(args: &[JsValue]) -> Option<Rc<RefCell<BTreeMap<String, JsValue>>>> {
    if let Some(JsValue::Object(ref o)) = args.first() {
        if let Some(JsValue::Object(ref s)) = o.borrow().get("_store") {
            return Some(s.clone());
        }
    }
    None
}

fn append(a: &[JsValue]) -> JsValue {
    let k = a.get(1).map(|v| v.to_string()).unwrap_or_default();
    let v = a.get(2).cloned().unwrap_or(JsValue::Undefined);
    if let Some(s) = store_ref(a) {
        s.borrow_mut().insert(k, v);
    }
    JsValue::Undefined
}

fn get(a: &[JsValue]) -> JsValue {
    let k = a.get(1).map(|v| v.to_string()).unwrap_or_default();
    store_ref(a).and_then(|s| s.borrow().get(&k).cloned()).unwrap_or(JsValue::Null)
}

fn get_all(a: &[JsValue]) -> JsValue {
    let k = a.get(1).map(|v| v.to_string()).unwrap_or_default();
    if let Some(s) = store_ref(a) {
        let vals: Vec<JsValue> = s.borrow().get(&k).cloned().into_iter().collect();
        return JsValue::Array(Rc::new(RefCell::new(vals)));
    }
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}

fn has(a: &[JsValue]) -> JsValue {
    let k = a.get(1).map(|v| v.to_string()).unwrap_or_default();
    JsValue::Bool(store_ref(a).map(|s| s.borrow().contains_key(&k)).unwrap_or(false))
}

fn delete(a: &[JsValue]) -> JsValue {
    let k = a.get(1).map(|v| v.to_string()).unwrap_or_default();
    if let Some(s) = store_ref(a) {
        s.borrow_mut().remove(&k);
    }
    JsValue::Undefined
}

fn entries(a: &[JsValue]) -> JsValue {
    if let Some(s) = store_ref(a) {
        let items: Vec<JsValue> = s
            .borrow()
            .iter()
            .map(|(k, v)| {
                JsValue::Array(Rc::new(RefCell::new(alloc::vec![
                    JsValue::String(k.clone()),
                    v.clone()
                ])))
            })
            .collect();
        return JsValue::Array(Rc::new(RefCell::new(items)));
    }
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
