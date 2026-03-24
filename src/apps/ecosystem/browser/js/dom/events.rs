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

pub struct JsEvent { pub event_type: String, pub target: Option<JsValue>, pub bubbles: bool, pub cancelable: bool }

impl JsEvent {
    pub fn new(event_type: &str) -> Self { Self { event_type: String::from(event_type), target: None, bubbles: true, cancelable: true } }
    pub fn to_js_value(&self) -> JsValue {
        let mut obj = BTreeMap::new();
        obj.insert(String::from("type"), JsValue::String(self.event_type.clone()));
        obj.insert(String::from("target"), self.target.clone().unwrap_or(JsValue::Null));
        obj.insert(String::from("currentTarget"), self.target.clone().unwrap_or(JsValue::Null));
        obj.insert(String::from("bubbles"), JsValue::Bool(self.bubbles));
        obj.insert(String::from("cancelable"), JsValue::Bool(self.cancelable));
        obj.insert(String::from("defaultPrevented"), JsValue::Bool(false));
        obj.insert(String::from("eventPhase"), JsValue::Number(2.0));
        obj.insert(String::from("timeStamp"), JsValue::Number(0.0));
        obj.insert(String::from("isTrusted"), JsValue::Bool(true));
        obj.insert(String::from("preventDefault"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("stopPropagation"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("stopImmediatePropagation"), JsValue::NativeFunc(|_| JsValue::Undefined));
        JsValue::Object(Rc::new(RefCell::new(obj)))
    }
}

pub struct JsMouseEvent { pub base: JsEvent, pub client_x: i32, pub client_y: i32, pub button: u8 }

impl JsMouseEvent {
    pub fn new(event_type: &str, x: i32, y: i32, button: u8) -> Self { Self { base: JsEvent::new(event_type), client_x: x, client_y: y, button } }
    pub fn to_js_value(&self) -> JsValue {
        let mut obj = BTreeMap::new();
        obj.insert(String::from("type"), JsValue::String(self.base.event_type.clone()));
        obj.insert(String::from("clientX"), JsValue::Number(self.client_x as f64));
        obj.insert(String::from("clientY"), JsValue::Number(self.client_y as f64));
        obj.insert(String::from("pageX"), JsValue::Number(self.client_x as f64));
        obj.insert(String::from("pageY"), JsValue::Number(self.client_y as f64));
        obj.insert(String::from("screenX"), JsValue::Number(self.client_x as f64));
        obj.insert(String::from("screenY"), JsValue::Number(self.client_y as f64));
        obj.insert(String::from("offsetX"), JsValue::Number(0.0));
        obj.insert(String::from("offsetY"), JsValue::Number(0.0));
        obj.insert(String::from("button"), JsValue::Number(self.button as f64));
        obj.insert(String::from("buttons"), JsValue::Number(if self.button == 0 { 1.0 } else { 0.0 }));
        obj.insert(String::from("altKey"), JsValue::Bool(false));
        obj.insert(String::from("ctrlKey"), JsValue::Bool(false));
        obj.insert(String::from("shiftKey"), JsValue::Bool(false));
        obj.insert(String::from("metaKey"), JsValue::Bool(false));
        obj.insert(String::from("preventDefault"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("stopPropagation"), JsValue::NativeFunc(|_| JsValue::Undefined));
        JsValue::Object(Rc::new(RefCell::new(obj)))
    }
}

pub struct JsKeyboardEvent { pub base: JsEvent, pub key: String, pub code: String, pub key_code: u32 }

impl JsKeyboardEvent {
    pub fn new(event_type: &str, key: &str, code: &str, key_code: u32) -> Self { Self { base: JsEvent::new(event_type), key: String::from(key), code: String::from(code), key_code } }
    pub fn to_js_value(&self) -> JsValue {
        let mut obj = BTreeMap::new();
        obj.insert(String::from("type"), JsValue::String(self.base.event_type.clone()));
        obj.insert(String::from("key"), JsValue::String(self.key.clone()));
        obj.insert(String::from("code"), JsValue::String(self.code.clone()));
        obj.insert(String::from("keyCode"), JsValue::Number(self.key_code as f64));
        obj.insert(String::from("which"), JsValue::Number(self.key_code as f64));
        obj.insert(String::from("altKey"), JsValue::Bool(false));
        obj.insert(String::from("ctrlKey"), JsValue::Bool(false));
        obj.insert(String::from("shiftKey"), JsValue::Bool(false));
        obj.insert(String::from("metaKey"), JsValue::Bool(false));
        obj.insert(String::from("repeat"), JsValue::Bool(false));
        obj.insert(String::from("isComposing"), JsValue::Bool(false));
        obj.insert(String::from("preventDefault"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("stopPropagation"), JsValue::NativeFunc(|_| JsValue::Undefined));
        JsValue::Object(Rc::new(RefCell::new(obj)))
    }
}
