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

pub fn create_regexp_constructor() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("prototype"), create_regexp_prototype());
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn create_regexp_prototype() -> JsValue {
    let mut proto = BTreeMap::new();
    proto.insert(String::from("test"), JsValue::NativeFunc(regexp_test));
    proto.insert(String::from("exec"), JsValue::NativeFunc(regexp_exec));
    proto.insert(String::from("toString"), JsValue::NativeFunc(regexp_to_string));
    JsValue::Object(Rc::new(RefCell::new(proto)))
}

fn regexp_test(_args: &[JsValue]) -> JsValue {
    JsValue::Bool(false)
}
fn regexp_exec(_args: &[JsValue]) -> JsValue {
    JsValue::Null
}
fn regexp_to_string(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::from("/(?:)/"))
}
