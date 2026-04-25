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

pub fn create_websocket_constructor() -> JsValue {
    JsValue::NativeFunc(websocket_constructor)
}

fn websocket_constructor(args: &[JsValue]) -> JsValue {
    let url = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    let mut obj = BTreeMap::new();
    obj.insert(String::from("url"), JsValue::String(url));
    obj.insert(String::from("readyState"), JsValue::Number(0.0));
    obj.insert(String::from("bufferedAmount"), JsValue::Number(0.0));
    obj.insert(String::from("extensions"), JsValue::String(String::new()));
    obj.insert(String::from("protocol"), JsValue::String(String::new()));
    obj.insert(String::from("binaryType"), JsValue::String(String::from("blob")));
    obj.insert(String::from("onopen"), JsValue::Null);
    obj.insert(String::from("onmessage"), JsValue::Null);
    obj.insert(String::from("onerror"), JsValue::Null);
    obj.insert(String::from("onclose"), JsValue::Null);
    obj.insert(String::from("send"), JsValue::NativeFunc(websocket_send));
    obj.insert(String::from("close"), JsValue::NativeFunc(websocket_close));
    obj.insert(String::from("addEventListener"), JsValue::NativeFunc(websocket_add_event_listener));
    obj.insert(
        String::from("removeEventListener"),
        JsValue::NativeFunc(websocket_remove_event_listener),
    );
    obj.insert(String::from("CONNECTING"), JsValue::Number(0.0));
    obj.insert(String::from("OPEN"), JsValue::Number(1.0));
    obj.insert(String::from("CLOSING"), JsValue::Number(2.0));
    obj.insert(String::from("CLOSED"), JsValue::Number(3.0));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn websocket_send(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn websocket_close(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn websocket_add_event_listener(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn websocket_remove_event_listener(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
