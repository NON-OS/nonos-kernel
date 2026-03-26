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

pub fn create_storage() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("length"), JsValue::Number(0.0));
    obj.insert(String::from("getItem"), JsValue::NativeFunc(storage_get_item));
    obj.insert(String::from("setItem"), JsValue::NativeFunc(storage_set_item));
    obj.insert(String::from("removeItem"), JsValue::NativeFunc(storage_remove_item));
    obj.insert(String::from("clear"), JsValue::NativeFunc(storage_clear));
    obj.insert(String::from("key"), JsValue::NativeFunc(storage_key));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn storage_get_item(args: &[JsValue]) -> JsValue {
    let _key = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    JsValue::Null
}

fn storage_set_item(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn storage_remove_item(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn storage_clear(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
fn storage_key(_args: &[JsValue]) -> JsValue { JsValue::Null }
