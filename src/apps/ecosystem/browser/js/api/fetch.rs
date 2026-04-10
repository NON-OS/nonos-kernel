extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use spin::Mutex;
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use crate::apps::ecosystem::browser::js::promise;
use crate::apps::ecosystem::browser::js::security::{
    same_origin_check, SopDecision, cors_check, CorsRequest, CorsResult,
    block_mixed_content, upgrade_insecure_request, should_block_nosniff,
    csp_allows, CspPolicy, Origin, exposed_headers,
};
use super::headers_api;

static PAGE_URL: Mutex<Option<String>> = Mutex::new(None);

pub fn set_page_url(url: &str) { *PAGE_URL.lock() = Some(String::from(url)); }
fn get_page_url() -> String { PAGE_URL.lock().clone().unwrap_or_default() }

pub fn create_fetch_api() -> JsValue { JsValue::NativeFunc(native_fetch) }

fn native_fetch(args: &[JsValue]) -> JsValue {
    let url = args.first().map(|v| v.to_string()).unwrap_or_default();
    let page_url = get_page_url();

    if block_mixed_content(&page_url, &url) {
        let upgraded = upgrade_insecure_request(&page_url, &url);
        return fetch_with_security(&upgraded, &page_url, args);
    }
    fetch_with_security(&url, &page_url, args)
}

fn fetch_with_security(url: &str, page_url: &str, args: &[JsValue]) -> JsValue {
    let sop_result = same_origin_check(url, page_url);
    let method = extract_method(args);
    let headers = extract_headers(args);

    if sop_result == SopDecision::Block {
        let cors_req = CorsRequest {
            origin: Origin::from_url(page_url),
            method: method.clone(),
            headers: headers.clone(),
        };
        let cors_result = cors_check(&cors_req, Some("*"), Some(&method), None);
        if cors_result == CorsResult::Blocked {
            return create_error_response("CORS blocked");
        }
    }

    let response_headers: Vec<(String, String)> = Vec::new();
    let _exposed = exposed_headers(None);
    let response = create_response(200, "", &response_headers);
    JsValue::Promise(promise::promise_resolve(response))
}

fn extract_method(args: &[JsValue]) -> String {
    if let Some(JsValue::Object(opts)) = args.get(1) {
        if let Some(JsValue::String(m)) = opts.borrow().get("method") {
            return m.clone();
        }
    }
    String::from("GET")
}

fn extract_headers(args: &[JsValue]) -> Vec<String> {
    let mut result = Vec::new();
    if let Some(JsValue::Object(opts)) = args.get(1) {
        if let Some(JsValue::Object(hdrs)) = opts.borrow().get("headers") {
            for key in hdrs.borrow().keys() {
                result.push(key.clone());
            }
        }
    }
    result
}

fn create_error_response(msg: &str) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("ok"), JsValue::Bool(false));
    obj.insert(String::from("status"), JsValue::Number(0.0));
    obj.insert(String::from("statusText"), JsValue::String(String::from(msg)));
    obj.insert(String::from("type"), JsValue::String(String::from("error")));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

pub fn check_script_csp(policy: &CspPolicy, src: &str, page_url: &str) -> bool {
    csp_allows(policy, "script-src", src, page_url)
}

pub fn check_nosniff(content_type: Option<&str>, expected: &str) -> bool {
    should_block_nosniff(content_type, expected)
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
