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
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;

pub fn create_xhr_constructor() -> JsValue {
    JsValue::NativeFunc(xhr_constructor)
}

fn xhr_constructor(_args: &[JsValue]) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("readyState"), JsValue::Number(0.0));
    obj.insert(String::from("status"), JsValue::Number(0.0));
    obj.insert(String::from("statusText"), JsValue::String(String::new()));
    obj.insert(String::from("responseText"), JsValue::String(String::new()));
    obj.insert(String::from("responseXML"), JsValue::Null);
    obj.insert(String::from("response"), JsValue::String(String::new()));
    obj.insert(String::from("responseType"), JsValue::String(String::new()));
    obj.insert(String::from("responseURL"), JsValue::String(String::new()));
    obj.insert(String::from("timeout"), JsValue::Number(0.0));
    obj.insert(String::from("withCredentials"), JsValue::Bool(false));
    obj.insert(String::from("upload"), JsValue::Null);
    obj.insert(String::from("_method"), JsValue::String(String::new()));
    obj.insert(String::from("_url"), JsValue::String(String::new()));
    obj.insert(String::from("_headers"), JsValue::Object(Rc::new(RefCell::new(BTreeMap::new()))));
    obj.insert(String::from("onreadystatechange"), JsValue::Null);
    obj.insert(String::from("onload"), JsValue::Null);
    obj.insert(String::from("onerror"), JsValue::Null);
    obj.insert(String::from("onprogress"), JsValue::Null);
    obj.insert(String::from("onabort"), JsValue::Null);
    obj.insert(String::from("ontimeout"), JsValue::Null);
    obj.insert(String::from("onloadstart"), JsValue::Null);
    obj.insert(String::from("onloadend"), JsValue::Null);
    obj.insert(String::from("open"), JsValue::NativeFunc(xhr_open));
    obj.insert(String::from("send"), JsValue::NativeFunc(xhr_send));
    obj.insert(String::from("abort"), JsValue::NativeFunc(xhr_abort));
    obj.insert(String::from("setRequestHeader"), JsValue::NativeFunc(xhr_set_request_header));
    obj.insert(String::from("getResponseHeader"), JsValue::NativeFunc(xhr_get_response_header));
    obj.insert(
        String::from("getAllResponseHeaders"),
        JsValue::NativeFunc(xhr_get_all_response_headers),
    );
    obj.insert(String::from("overrideMimeType"), JsValue::NativeFunc(xhr_override_mime_type));
    obj.insert(String::from("UNSENT"), JsValue::Number(0.0));
    obj.insert(String::from("OPENED"), JsValue::Number(1.0));
    obj.insert(String::from("HEADERS_RECEIVED"), JsValue::Number(2.0));
    obj.insert(String::from("LOADING"), JsValue::Number(3.0));
    obj.insert(String::from("DONE"), JsValue::Number(4.0));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn xhr_open(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn xhr_send(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn xhr_abort(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn xhr_set_request_header(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn xhr_get_response_header(_args: &[JsValue]) -> JsValue {
    JsValue::Null
}
fn xhr_get_all_response_headers(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn xhr_override_mime_type(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
