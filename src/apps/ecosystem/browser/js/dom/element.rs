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
use alloc::vec::Vec;
use core::cell::RefCell;

pub struct JsElement {
    pub tag: String,
    pub attrs: BTreeMap<String, String>,
    pub children: Vec<JsElement>,
    pub text: String,
}

impl JsElement {
    pub fn new(tag: &str) -> Self {
        Self {
            tag: String::from(tag),
            attrs: BTreeMap::new(),
            children: Vec::new(),
            text: String::new(),
        }
    }
    pub fn to_js_value(&self) -> JsValue {
        let mut obj = BTreeMap::new();
        obj.insert(String::from("tagName"), JsValue::String(self.tag.to_uppercase()));
        obj.insert(String::from("nodeType"), JsValue::Number(1.0));
        obj.insert(String::from("textContent"), JsValue::String(self.text.clone()));
        obj.insert(String::from("innerHTML"), JsValue::String(self.text.clone()));
        obj.insert(
            String::from("id"),
            self.attrs
                .get("id")
                .map(|s| JsValue::String(s.clone()))
                .unwrap_or(JsValue::String(String::new())),
        );
        obj.insert(
            String::from("className"),
            self.attrs
                .get("class")
                .map(|s| JsValue::String(s.clone()))
                .unwrap_or(JsValue::String(String::new())),
        );
        obj.insert(String::from("style"), self.create_style_object());
        obj.insert(String::from("children"), self.create_children_array());
        obj.insert(
            String::from("firstChild"),
            if self.children.is_empty() { JsValue::Null } else { self.children[0].to_js_value() },
        );
        obj.insert(
            String::from("lastChild"),
            self.children.last().map(|c| c.to_js_value()).unwrap_or(JsValue::Null),
        );
        obj.insert(String::from("parentNode"), JsValue::Null);
        obj.insert(String::from("nextSibling"), JsValue::Null);
        obj.insert(String::from("previousSibling"), JsValue::Null);
        obj.insert(
            String::from("appendChild"),
            JsValue::NativeFunc(|args| args.get(0).cloned().unwrap_or(JsValue::Undefined)),
        );
        obj.insert(
            String::from("removeChild"),
            JsValue::NativeFunc(|args| args.get(0).cloned().unwrap_or(JsValue::Undefined)),
        );
        obj.insert(
            String::from("insertBefore"),
            JsValue::NativeFunc(|args| args.get(0).cloned().unwrap_or(JsValue::Undefined)),
        );
        obj.insert(
            String::from("replaceChild"),
            JsValue::NativeFunc(|args| args.get(0).cloned().unwrap_or(JsValue::Undefined)),
        );
        obj.insert(String::from("cloneNode"), JsValue::NativeFunc(|_| JsValue::Null));
        obj.insert(String::from("contains"), JsValue::NativeFunc(|_| JsValue::Bool(false)));
        obj.insert(String::from("setAttribute"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("getAttribute"), JsValue::NativeFunc(|_| JsValue::Null));
        obj.insert(String::from("removeAttribute"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("hasAttribute"), JsValue::NativeFunc(|_| JsValue::Bool(false)));
        obj.insert(String::from("addEventListener"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(
            String::from("removeEventListener"),
            JsValue::NativeFunc(|_| JsValue::Undefined),
        );
        obj.insert(String::from("dispatchEvent"), JsValue::NativeFunc(|_| JsValue::Bool(true)));
        obj.insert(String::from("focus"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("blur"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("click"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(
            String::from("getBoundingClientRect"),
            JsValue::NativeFunc(native_get_bounding_rect),
        );
        obj.insert(String::from("querySelector"), JsValue::NativeFunc(|_| JsValue::Null));
        obj.insert(
            String::from("querySelectorAll"),
            JsValue::NativeFunc(|_| JsValue::Array(Rc::new(RefCell::new(Vec::new())))),
        );
        JsValue::Object(Rc::new(RefCell::new(obj)))
    }
    fn create_style_object(&self) -> JsValue {
        JsValue::Object(Rc::new(RefCell::new(BTreeMap::new())))
    }
    fn create_children_array(&self) -> JsValue {
        JsValue::Array(Rc::new(RefCell::new(
            self.children.iter().map(|c| c.to_js_value()).collect(),
        )))
    }
}

fn native_get_bounding_rect(_args: &[JsValue]) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("x"), JsValue::Number(0.0));
    obj.insert(String::from("y"), JsValue::Number(0.0));
    obj.insert(String::from("width"), JsValue::Number(0.0));
    obj.insert(String::from("height"), JsValue::Number(0.0));
    obj.insert(String::from("top"), JsValue::Number(0.0));
    obj.insert(String::from("right"), JsValue::Number(0.0));
    obj.insert(String::from("bottom"), JsValue::Number(0.0));
    obj.insert(String::from("left"), JsValue::Number(0.0));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}
