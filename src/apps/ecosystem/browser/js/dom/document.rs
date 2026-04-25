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
use crate::apps::ecosystem::browser::engine::Document;
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

pub struct JsDocument {
    pub doc: Rc<RefCell<Document>>,
}

impl JsDocument {
    pub fn new(doc: Document) -> Self {
        Self { doc: Rc::new(RefCell::new(doc)) }
    }
    pub fn to_js_value(&self) -> JsValue {
        let mut obj = BTreeMap::new();
        obj.insert(String::from("title"), JsValue::String(self.doc.borrow().title.clone()));
        obj.insert(String::from("getElementById"), JsValue::NativeFunc(native_get_element_by_id));
        obj.insert(
            String::from("getElementsByClassName"),
            JsValue::NativeFunc(native_get_elements_by_class),
        );
        obj.insert(
            String::from("getElementsByTagName"),
            JsValue::NativeFunc(native_get_elements_by_tag),
        );
        obj.insert(String::from("querySelector"), JsValue::NativeFunc(native_query_selector));
        obj.insert(
            String::from("querySelectorAll"),
            JsValue::NativeFunc(native_query_selector_all),
        );
        obj.insert(String::from("createElement"), JsValue::NativeFunc(native_create_element));
        obj.insert(String::from("createTextNode"), JsValue::NativeFunc(native_create_text_node));
        obj.insert(String::from("body"), create_body_element());
        obj.insert(String::from("head"), create_head_element());
        obj.insert(String::from("documentElement"), create_html_element());
        JsValue::Object(Rc::new(RefCell::new(obj)))
    }
}

fn native_get_element_by_id(args: &[JsValue]) -> JsValue {
    let _id = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    create_mock_element()
}
fn native_get_elements_by_class(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn native_get_elements_by_tag(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn native_query_selector(_args: &[JsValue]) -> JsValue {
    JsValue::Null
}
fn native_query_selector_all(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn native_create_element(args: &[JsValue]) -> JsValue {
    let tag = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    create_element_with_tag(&tag)
}
fn native_create_text_node(args: &[JsValue]) -> JsValue {
    let text = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    let mut obj = BTreeMap::new();
    obj.insert(String::from("nodeType"), JsValue::Number(3.0));
    obj.insert(String::from("textContent"), JsValue::String(text));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}
fn create_mock_element() -> JsValue {
    create_element_with_tag("div")
}
fn create_body_element() -> JsValue {
    create_element_with_tag("body")
}
fn create_head_element() -> JsValue {
    create_element_with_tag("head")
}
fn create_html_element() -> JsValue {
    create_element_with_tag("html")
}
fn create_element_with_tag(tag: &str) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("tagName"), JsValue::String(String::from(tag).to_uppercase()));
    obj.insert(String::from("nodeType"), JsValue::Number(1.0));
    obj.insert(String::from("innerHTML"), JsValue::String(String::new()));
    obj.insert(String::from("textContent"), JsValue::String(String::new()));
    obj.insert(String::from("style"), JsValue::Object(Rc::new(RefCell::new(BTreeMap::new()))));
    obj.insert(String::from("children"), JsValue::Array(Rc::new(RefCell::new(Vec::new()))));
    obj.insert(
        String::from("appendChild"),
        JsValue::NativeFunc(|args| args.get(0).cloned().unwrap_or(JsValue::Undefined)),
    );
    obj.insert(
        String::from("removeChild"),
        JsValue::NativeFunc(|args| args.get(0).cloned().unwrap_or(JsValue::Undefined)),
    );
    obj.insert(String::from("setAttribute"), JsValue::NativeFunc(|_| JsValue::Undefined));
    obj.insert(String::from("getAttribute"), JsValue::NativeFunc(|_| JsValue::Null));
    obj.insert(String::from("addEventListener"), JsValue::NativeFunc(|_| JsValue::Undefined));
    obj.insert(String::from("removeEventListener"), JsValue::NativeFunc(|_| JsValue::Undefined));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}
