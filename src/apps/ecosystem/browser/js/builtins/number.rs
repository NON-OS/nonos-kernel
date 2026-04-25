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

pub fn create_number_constructor() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("MAX_VALUE"), JsValue::Number(f64::MAX));
    obj.insert(String::from("MIN_VALUE"), JsValue::Number(f64::MIN_POSITIVE));
    obj.insert(String::from("MAX_SAFE_INTEGER"), JsValue::Number(9007199254740991.0));
    obj.insert(String::from("MIN_SAFE_INTEGER"), JsValue::Number(-9007199254740991.0));
    obj.insert(String::from("POSITIVE_INFINITY"), JsValue::Number(f64::INFINITY));
    obj.insert(String::from("NEGATIVE_INFINITY"), JsValue::Number(f64::NEG_INFINITY));
    obj.insert(String::from("NaN"), JsValue::Number(f64::NAN));
    obj.insert(String::from("EPSILON"), JsValue::Number(f64::EPSILON));
    obj.insert(String::from("isNaN"), JsValue::NativeFunc(number_is_nan));
    obj.insert(String::from("isFinite"), JsValue::NativeFunc(number_is_finite));
    obj.insert(String::from("isInteger"), JsValue::NativeFunc(number_is_integer));
    obj.insert(String::from("isSafeInteger"), JsValue::NativeFunc(number_is_safe_integer));
    obj.insert(String::from("parseFloat"), JsValue::NativeFunc(number_parse_float));
    obj.insert(String::from("parseInt"), JsValue::NativeFunc(number_parse_int));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn number_is_nan(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Number(n)) = args.get(0) {
        JsValue::Bool(n.is_nan())
    } else {
        JsValue::Bool(false)
    }
}
fn number_is_finite(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Number(n)) = args.get(0) {
        JsValue::Bool(n.is_finite())
    } else {
        JsValue::Bool(false)
    }
}
fn number_is_integer(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Number(n)) = args.get(0) {
        JsValue::Bool(n.is_finite() && libm::trunc(*n) == *n)
    } else {
        JsValue::Bool(false)
    }
}
fn number_is_safe_integer(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Number(n)) = args.get(0) {
        JsValue::Bool(
            n.is_finite() && libm::trunc(*n) == *n && libm::fabs(*n) <= 9007199254740991.0,
        )
    } else {
        JsValue::Bool(false)
    }
}
fn number_parse_float(args: &[JsValue]) -> JsValue {
    let s = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    JsValue::Number(s.trim().parse().unwrap_or(f64::NAN))
}
fn number_parse_int(args: &[JsValue]) -> JsValue {
    let s = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    let radix = args.get(1).map(|v| v.to_number() as u32).unwrap_or(10);
    JsValue::Number(i64::from_str_radix(s.trim(), radix).map(|n| n as f64).unwrap_or(f64::NAN))
}
