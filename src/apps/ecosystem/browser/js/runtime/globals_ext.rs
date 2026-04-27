extern crate alloc;
use super::scope::Scope;
use super::value::JsValue;
use crate::apps::ecosystem::browser::js::promise;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;

pub(super) fn register_all(scope: &mut Scope) {
    register_error_constructors(scope);
    register_promise_statics(scope);
}

fn register_error_constructors(scope: &mut Scope) {
    scope.declare(String::from("Error"), JsValue::NativeFunc(error_ctor));
    scope.declare(String::from("TypeError"), JsValue::NativeFunc(type_error_ctor));
    scope.declare(String::from("RangeError"), JsValue::NativeFunc(range_error_ctor));
    scope.declare(String::from("SyntaxError"), JsValue::NativeFunc(syntax_error_ctor));
    scope.declare(String::from("ReferenceError"), JsValue::NativeFunc(ref_error_ctor));
}

fn register_promise_statics(scope: &mut Scope) {
    let mut promise_obj = BTreeMap::new();
    promise_obj.insert(String::from("resolve"), JsValue::NativeFunc(promise_resolve));
    promise_obj.insert(String::from("reject"), JsValue::NativeFunc(promise_reject));
    scope.declare(String::from("Promise"), JsValue::Object(Rc::new(RefCell::new(promise_obj))));
}

fn make_error_obj(name: &str, args: &[JsValue]) -> JsValue {
    let msg = args.first().map(|v| v.to_string()).unwrap_or_default();
    let mut obj = BTreeMap::new();
    obj.insert(String::from("name"), JsValue::String(String::from(name)));
    obj.insert(String::from("message"), JsValue::String(msg.clone()));
    obj.insert(String::from("stack"), JsValue::String(alloc::format!("{}: {}", name, msg)));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn error_ctor(args: &[JsValue]) -> JsValue {
    make_error_obj("Error", args)
}
fn type_error_ctor(args: &[JsValue]) -> JsValue {
    make_error_obj("TypeError", args)
}
fn range_error_ctor(args: &[JsValue]) -> JsValue {
    make_error_obj("RangeError", args)
}
fn syntax_error_ctor(args: &[JsValue]) -> JsValue {
    make_error_obj("SyntaxError", args)
}
fn ref_error_ctor(args: &[JsValue]) -> JsValue {
    make_error_obj("ReferenceError", args)
}

fn promise_resolve(args: &[JsValue]) -> JsValue {
    let val = args.first().cloned().unwrap_or(JsValue::Undefined);
    JsValue::Promise(promise::promise_resolve(val))
}

fn promise_reject(args: &[JsValue]) -> JsValue {
    let val = args.first().cloned().unwrap_or(JsValue::Undefined);
    JsValue::Promise(promise::promise_reject(val))
}
