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

pub fn create_object_constructor() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("keys"), JsValue::NativeFunc(object_keys));
    obj.insert(String::from("values"), JsValue::NativeFunc(object_values));
    obj.insert(String::from("entries"), JsValue::NativeFunc(object_entries));
    obj.insert(String::from("assign"), JsValue::NativeFunc(object_assign));
    obj.insert(String::from("freeze"), JsValue::NativeFunc(object_freeze));
    obj.insert(String::from("seal"), JsValue::NativeFunc(object_seal));
    obj.insert(String::from("create"), JsValue::NativeFunc(object_create));
    obj.insert(String::from("defineProperty"), JsValue::NativeFunc(object_define_property));
    obj.insert(String::from("defineProperties"), JsValue::NativeFunc(object_define_properties));
    obj.insert(
        String::from("getOwnPropertyNames"),
        JsValue::NativeFunc(object_get_own_property_names),
    );
    obj.insert(
        String::from("getOwnPropertyDescriptor"),
        JsValue::NativeFunc(object_get_own_property_descriptor),
    );
    obj.insert(String::from("getPrototypeOf"), JsValue::NativeFunc(object_get_prototype_of));
    obj.insert(String::from("setPrototypeOf"), JsValue::NativeFunc(object_set_prototype_of));
    obj.insert(String::from("is"), JsValue::NativeFunc(object_is));
    obj.insert(String::from("fromEntries"), JsValue::NativeFunc(object_from_entries));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn object_keys(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Object(o)) = args.get(0) {
        let keys: Vec<JsValue> = o.borrow().keys().map(|k| JsValue::String(k.clone())).collect();
        JsValue::Array(Rc::new(RefCell::new(keys)))
    } else {
        JsValue::Array(Rc::new(RefCell::new(Vec::new())))
    }
}
fn object_values(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Object(o)) = args.get(0) {
        let vals: Vec<JsValue> = o.borrow().values().cloned().collect();
        JsValue::Array(Rc::new(RefCell::new(vals)))
    } else {
        JsValue::Array(Rc::new(RefCell::new(Vec::new())))
    }
}
fn object_entries(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Object(o)) = args.get(0) {
        let entries: Vec<JsValue> = o
            .borrow()
            .iter()
            .map(|(k, v)| {
                JsValue::Array(Rc::new(RefCell::new(alloc::vec![
                    JsValue::String(k.clone()),
                    v.clone()
                ])))
            })
            .collect();
        JsValue::Array(Rc::new(RefCell::new(entries)))
    } else {
        JsValue::Array(Rc::new(RefCell::new(Vec::new())))
    }
}
fn object_assign(args: &[JsValue]) -> JsValue {
    args.get(0).cloned().unwrap_or(JsValue::Object(Rc::new(RefCell::new(BTreeMap::new()))))
}
fn object_freeze(args: &[JsValue]) -> JsValue {
    args.get(0).cloned().unwrap_or(JsValue::Undefined)
}
fn object_seal(args: &[JsValue]) -> JsValue {
    args.get(0).cloned().unwrap_or(JsValue::Undefined)
}
fn object_create(_args: &[JsValue]) -> JsValue {
    JsValue::Object(Rc::new(RefCell::new(BTreeMap::new())))
}
fn object_define_property(args: &[JsValue]) -> JsValue {
    args.get(0).cloned().unwrap_or(JsValue::Undefined)
}
fn object_define_properties(args: &[JsValue]) -> JsValue {
    args.get(0).cloned().unwrap_or(JsValue::Undefined)
}
fn object_get_own_property_names(args: &[JsValue]) -> JsValue {
    object_keys(args)
}
fn object_get_own_property_descriptor(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn object_get_prototype_of(_args: &[JsValue]) -> JsValue {
    JsValue::Null
}
fn object_set_prototype_of(args: &[JsValue]) -> JsValue {
    args.get(0).cloned().unwrap_or(JsValue::Undefined)
}
fn object_is(_args: &[JsValue]) -> JsValue {
    JsValue::Bool(false)
}
fn object_from_entries(_args: &[JsValue]) -> JsValue {
    JsValue::Object(Rc::new(RefCell::new(BTreeMap::new())))
}
