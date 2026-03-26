// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use alloc::string::String;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use crate::apps::ecosystem::browser::js::runtime::JsValue;

pub fn create_fetch_api() -> JsValue { JsValue::NativeFunc(native_fetch) }

fn native_fetch(args: &[JsValue]) -> JsValue {
    let _url = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    let _options = args.get(1);
    create_promise(create_response(200, "", &[]))
}

pub(super) fn create_promise(value: JsValue) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("_value"), value);
    obj.insert(String::from("_state"), JsValue::String(String::from("pending")));
    obj.insert(String::from("then"), JsValue::NativeFunc(promise_then));
    obj.insert(String::from("catch"), JsValue::NativeFunc(promise_catch));
    obj.insert(String::from("finally"), JsValue::NativeFunc(promise_finally));
    JsValue::Object(Rc::new(RefCell::new(obj)))
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
    obj.insert(String::from("headers"), create_headers(headers));
    obj.insert(String::from("text"), JsValue::NativeFunc(response_text));
    obj.insert(String::from("json"), JsValue::NativeFunc(response_json));
    obj.insert(String::from("blob"), JsValue::NativeFunc(response_blob));
    obj.insert(String::from("arrayBuffer"), JsValue::NativeFunc(response_array_buffer));
    obj.insert(String::from("clone"), JsValue::NativeFunc(response_clone));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn create_headers(headers: &[(String, String)]) -> JsValue {
    let mut obj = BTreeMap::new();
    for (k, v) in headers { obj.insert(k.clone(), JsValue::String(v.clone())); }
    obj.insert(String::from("get"), JsValue::NativeFunc(headers_get));
    obj.insert(String::from("set"), JsValue::NativeFunc(headers_set));
    obj.insert(String::from("has"), JsValue::NativeFunc(headers_has));
    obj.insert(String::from("delete"), JsValue::NativeFunc(headers_delete));
    obj.insert(String::from("append"), JsValue::NativeFunc(headers_append));
    obj.insert(String::from("entries"), JsValue::NativeFunc(headers_entries));
    obj.insert(String::from("keys"), JsValue::NativeFunc(headers_keys));
    obj.insert(String::from("values"), JsValue::NativeFunc(headers_values));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn status_text(status: u16) -> String {
    String::from(match status { 200 => "OK", 201 => "Created", 204 => "No Content", 301 => "Moved Permanently", 302 => "Found", 304 => "Not Modified", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found", 500 => "Internal Server Error", _ => "" })
}

fn promise_then(_args: &[JsValue]) -> JsValue { create_promise(JsValue::Undefined) }
fn promise_catch(_args: &[JsValue]) -> JsValue { create_promise(JsValue::Undefined) }
fn promise_finally(_args: &[JsValue]) -> JsValue { create_promise(JsValue::Undefined) }
fn response_text(_args: &[JsValue]) -> JsValue { create_promise(JsValue::String(String::new())) }
fn response_json(_args: &[JsValue]) -> JsValue { create_promise(JsValue::Object(Rc::new(RefCell::new(BTreeMap::new())))) }
fn response_blob(_args: &[JsValue]) -> JsValue { create_promise(JsValue::Undefined) }
fn response_array_buffer(_args: &[JsValue]) -> JsValue { create_promise(JsValue::Undefined) }
fn response_clone(_args: &[JsValue]) -> JsValue { create_response(200, "", &[]) }
fn headers_get(_args: &[JsValue]) -> JsValue { JsValue::Null }
fn headers_set(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn headers_has(_args: &[JsValue]) -> JsValue { JsValue::Bool(false) }
fn headers_delete(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn headers_append(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn headers_entries(_args: &[JsValue]) -> JsValue { JsValue::Array(Rc::new(RefCell::new(alloc::vec::Vec::new()))) }
fn headers_keys(_args: &[JsValue]) -> JsValue { JsValue::Array(Rc::new(RefCell::new(alloc::vec::Vec::new()))) }
fn headers_values(_args: &[JsValue]) -> JsValue { JsValue::Array(Rc::new(RefCell::new(alloc::vec::Vec::new()))) }
