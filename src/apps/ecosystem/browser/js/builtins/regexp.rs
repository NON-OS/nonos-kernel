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

pub fn create_regexp_constructor() -> JsValue {
    let obj: BTreeMap<String, JsValue> = BTreeMap::new();
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

pub fn create_regexp_instance(pattern: &str, flags: &str) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("source"), JsValue::String(String::from(pattern)));
    obj.insert(String::from("flags"), JsValue::String(String::from(flags)));
    obj.insert(String::from("global"), JsValue::Bool(flags.contains('g')));
    obj.insert(String::from("ignoreCase"), JsValue::Bool(flags.contains('i')));
    obj.insert(String::from("multiline"), JsValue::Bool(flags.contains('m')));
    obj.insert(String::from("sticky"), JsValue::Bool(flags.contains('y')));
    obj.insert(String::from("unicode"), JsValue::Bool(flags.contains('u')));
    obj.insert(String::from("dotAll"), JsValue::Bool(flags.contains('s')));
    obj.insert(String::from("lastIndex"), JsValue::Number(0.0));
    obj.insert(String::from("test"), JsValue::NativeFunc(regexp_test));
    obj.insert(String::from("exec"), JsValue::NativeFunc(regexp_exec));
    obj.insert(String::from("toString"), JsValue::NativeFunc(regexp_to_string));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn regexp_test(_args: &[JsValue]) -> JsValue { JsValue::Bool(false) }
fn regexp_exec(_args: &[JsValue]) -> JsValue { JsValue::Null }
fn regexp_to_string(_args: &[JsValue]) -> JsValue { JsValue::String(String::from("/(?:)/")) }
