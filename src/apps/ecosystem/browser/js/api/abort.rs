extern crate alloc;
use alloc::string::String;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use crate::apps::ecosystem::browser::js::runtime::JsValue;

pub fn create_abort_controller() -> JsValue {
    let signal = create_abort_signal();
    let mut obj = BTreeMap::new();
    obj.insert(String::from("signal"), signal);
    obj.insert(String::from("abort"), JsValue::NativeFunc(abort));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn create_abort_signal() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("aborted"), JsValue::Bool(false));
    obj.insert(String::from("reason"), JsValue::Undefined);
    obj.insert(String::from("onabort"), JsValue::Null);
    obj.insert(String::from("addEventListener"), JsValue::NativeFunc(add_listener));
    obj.insert(String::from("removeEventListener"), JsValue::NativeFunc(remove_listener));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn abort(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Object(ref ctrl)) = args.first() {
        if let Some(JsValue::Object(ref signal)) = ctrl.borrow().get("signal") {
            let reason = args.get(1).cloned().unwrap_or(JsValue::String(String::from("AbortError")));
            signal.borrow_mut().insert(String::from("aborted"), JsValue::Bool(true));
            signal.borrow_mut().insert(String::from("reason"), reason);
        }
    }
    JsValue::Undefined
}

fn add_listener(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn remove_listener(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
