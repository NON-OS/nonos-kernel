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

pub fn create_string_prototype() -> JsValue {
    let mut proto = BTreeMap::new();
    proto.insert(String::from("charAt"), JsValue::NativeFunc(string_char_at));
    proto.insert(String::from("charCodeAt"), JsValue::NativeFunc(string_char_code_at));
    proto.insert(String::from("concat"), JsValue::NativeFunc(string_concat));
    proto.insert(String::from("includes"), JsValue::NativeFunc(string_includes));
    proto.insert(String::from("endsWith"), JsValue::NativeFunc(string_ends_with));
    proto.insert(String::from("startsWith"), JsValue::NativeFunc(string_starts_with));
    proto.insert(String::from("indexOf"), JsValue::NativeFunc(string_index_of));
    proto.insert(String::from("lastIndexOf"), JsValue::NativeFunc(string_last_index_of));
    proto.insert(String::from("padStart"), JsValue::NativeFunc(string_pad_start));
    proto.insert(String::from("padEnd"), JsValue::NativeFunc(string_pad_end));
    proto.insert(String::from("repeat"), JsValue::NativeFunc(string_repeat));
    proto.insert(String::from("replace"), JsValue::NativeFunc(string_replace));
    proto.insert(String::from("slice"), JsValue::NativeFunc(string_slice));
    proto.insert(String::from("split"), JsValue::NativeFunc(string_split));
    proto.insert(String::from("substring"), JsValue::NativeFunc(string_substring));
    proto.insert(String::from("toLowerCase"), JsValue::NativeFunc(string_to_lower_case));
    proto.insert(String::from("toUpperCase"), JsValue::NativeFunc(string_to_upper_case));
    proto.insert(String::from("trim"), JsValue::NativeFunc(string_trim));
    proto.insert(String::from("trimStart"), JsValue::NativeFunc(string_trim_start));
    proto.insert(String::from("trimEnd"), JsValue::NativeFunc(string_trim_end));
    proto.insert(String::from("toString"), JsValue::NativeFunc(string_to_string));
    proto.insert(String::from("valueOf"), JsValue::NativeFunc(string_value_of));
    JsValue::Object(Rc::new(RefCell::new(proto)))
}

fn string_char_at(args: &[JsValue]) -> JsValue {
    let _idx = args.get(0).map(|v| v.to_number() as usize).unwrap_or(0);
    JsValue::String(String::new())
}
fn string_char_code_at(args: &[JsValue]) -> JsValue {
    let _idx = args.get(0).map(|v| v.to_number() as usize).unwrap_or(0);
    JsValue::Number(f64::NAN)
}
fn string_concat(args: &[JsValue]) -> JsValue {
    let mut s = String::new();
    for a in args {
        s.push_str(&a.to_string());
    }
    JsValue::String(s)
}
fn string_includes(_args: &[JsValue]) -> JsValue {
    JsValue::Bool(false)
}
fn string_ends_with(_args: &[JsValue]) -> JsValue {
    JsValue::Bool(false)
}
fn string_starts_with(_args: &[JsValue]) -> JsValue {
    JsValue::Bool(false)
}
fn string_index_of(_args: &[JsValue]) -> JsValue {
    JsValue::Number(-1.0)
}
fn string_last_index_of(_args: &[JsValue]) -> JsValue {
    JsValue::Number(-1.0)
}
fn string_pad_start(args: &[JsValue]) -> JsValue {
    JsValue::String(args.get(0).map(|v| v.to_string()).unwrap_or_default())
}
fn string_pad_end(args: &[JsValue]) -> JsValue {
    JsValue::String(args.get(0).map(|v| v.to_string()).unwrap_or_default())
}
fn string_repeat(args: &[JsValue]) -> JsValue {
    let _count = args.get(0).map(|v| v.to_number() as usize).unwrap_or(0);
    JsValue::String(String::new())
}
fn string_replace(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn string_slice(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn string_split(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(Vec::new())))
}
fn string_substring(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn string_to_lower_case(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn string_to_upper_case(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn string_trim(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn string_trim_start(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn string_trim_end(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn string_to_string(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
fn string_value_of(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::new())
}
