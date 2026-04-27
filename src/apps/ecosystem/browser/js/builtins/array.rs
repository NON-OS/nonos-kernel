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

pub fn create_array_prototype() -> JsValue {
    let mut proto = BTreeMap::new();
    proto.insert(String::from("push"), JsValue::NativeFunc(array_push));
    proto.insert(String::from("pop"), JsValue::NativeFunc(array_pop));
    proto.insert(String::from("shift"), JsValue::NativeFunc(array_shift));
    proto.insert(String::from("unshift"), JsValue::NativeFunc(array_unshift));
    proto.insert(String::from("slice"), JsValue::NativeFunc(array_slice));
    proto.insert(String::from("splice"), JsValue::NativeFunc(array_splice));
    proto.insert(String::from("concat"), JsValue::NativeFunc(array_concat));
    proto.insert(String::from("join"), JsValue::NativeFunc(array_join));
    proto.insert(String::from("reverse"), JsValue::NativeFunc(array_reverse));
    proto.insert(String::from("indexOf"), JsValue::NativeFunc(array_index_of));
    proto.insert(String::from("lastIndexOf"), JsValue::NativeFunc(array_last_index_of));
    proto.insert(String::from("includes"), JsValue::NativeFunc(array_includes));
    proto.insert(String::from("find"), JsValue::NativeFunc(array_find));
    proto.insert(String::from("findIndex"), JsValue::NativeFunc(array_find_index));
    proto.insert(String::from("filter"), JsValue::NativeFunc(array_filter));
    proto.insert(String::from("map"), JsValue::NativeFunc(array_map));
    proto.insert(String::from("forEach"), JsValue::NativeFunc(array_for_each));
    proto.insert(String::from("reduce"), JsValue::NativeFunc(array_reduce));
    proto.insert(String::from("some"), JsValue::NativeFunc(array_some));
    proto.insert(String::from("every"), JsValue::NativeFunc(array_every));
    proto.insert(String::from("fill"), JsValue::NativeFunc(array_fill));
    proto.insert(String::from("flat"), JsValue::NativeFunc(array_flat));
    proto.insert(String::from("toString"), JsValue::NativeFunc(array_to_string));
    JsValue::Object(Rc::new(RefCell::new(proto)))
}

fn array_push(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn array_pop(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn array_shift(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn array_unshift(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn array_slice(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn array_splice(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn array_concat(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn array_join(args: &[JsValue]) -> JsValue {
    let _sep = args.get(0).map(|v| v.to_string()).unwrap_or(String::from(","));
    JsValue::String(String::new())
}
fn array_reverse(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn array_index_of(_args: &[JsValue]) -> JsValue {
    JsValue::Number(-1.0)
}
fn array_last_index_of(_args: &[JsValue]) -> JsValue {
    JsValue::Number(-1.0)
}
fn array_includes(_args: &[JsValue]) -> JsValue {
    JsValue::Bool(false)
}
fn array_find(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn array_find_index(_args: &[JsValue]) -> JsValue {
    JsValue::Number(-1.0)
}
fn array_filter(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn array_map(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn array_for_each(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn array_reduce(args: &[JsValue]) -> JsValue {
    args.get(1).cloned().unwrap_or(JsValue::Undefined)
}
fn array_some(_args: &[JsValue]) -> JsValue {
    JsValue::Bool(false)
}
fn array_every(_args: &[JsValue]) -> JsValue {
    JsValue::Bool(true)
}
fn array_fill(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn array_flat(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn array_to_string(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
