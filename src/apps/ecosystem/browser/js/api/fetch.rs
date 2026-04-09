extern crate alloc;
use alloc::string::String;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use crate::apps::ecosystem::browser::js::promise;
use super::headers_api;

pub fn create_fetch_api() -> JsValue { JsValue::NativeFunc(native_fetch) }

fn native_fetch(args: &[JsValue]) -> JsValue {
    let _url = args.first().map(|v| v.to_string()).unwrap_or_default();
    let response = create_response(200, "", &[]);
    JsValue::Promise(promise::promise_resolve(response))
}

pub(super) fn create_response(status: u16, body: &str, headers: &[(String, String)]) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("ok"), JsValue::Bool(status >= 200 && status < 300));
    obj.insert(String::from("status"), JsValue::Number(status as f64));
    obj.insert(String::from("statusText"), JsValue::String(status_text(status)));
    obj.insert(String::from("url"), JsValue::String(String::new()));
    obj.insert(String::from("redirected"), JsValue::Bool(false));
    obj.insert(String::from("type"), JsValue::String(String::from("basic")));
    obj.insert(String::from("_body"), JsValue::String(String::from(body)));
    obj.insert(String::from("headers"), headers_api::create_headers(headers));
    obj.insert(String::from("text"), JsValue::NativeFunc(response_text));
    obj.insert(String::from("json"), JsValue::NativeFunc(response_json));
    obj.insert(String::from("clone"), JsValue::NativeFunc(response_clone));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn status_text(s: u16) -> String {
    String::from(match s { 200 => "OK", 201 => "Created", 204 => "No Content", 301 => "Moved Permanently", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found", 500 => "Internal Server Error", _ => "" })
}

fn extract_body(args: &[JsValue]) -> String {
    if let Some(JsValue::Object(ref obj)) = args.first() {
        obj.borrow().get("_body").map(|v| v.to_string()).unwrap_or_default()
    } else { String::new() }
}

fn response_text(args: &[JsValue]) -> JsValue {
    JsValue::Promise(promise::promise_resolve(JsValue::String(extract_body(args))))
}

fn response_json(args: &[JsValue]) -> JsValue {
    JsValue::Promise(promise::promise_resolve(JsValue::String(extract_body(args))))
}

fn response_clone(_args: &[JsValue]) -> JsValue { create_response(200, "", &[]) }
