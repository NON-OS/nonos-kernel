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
use super::natives;
use super::value::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;

pub(super) fn create_math() -> JsValue {
    let mut math = BTreeMap::new();
    math.insert(String::from("PI"), JsValue::Number(core::f64::consts::PI));
    math.insert(String::from("E"), JsValue::Number(core::f64::consts::E));
    math.insert(String::from("abs"), JsValue::NativeFunc(math_abs));
    math.insert(String::from("floor"), JsValue::NativeFunc(math_floor));
    math.insert(String::from("ceil"), JsValue::NativeFunc(math_ceil));
    math.insert(String::from("round"), JsValue::NativeFunc(math_round));
    math.insert(String::from("sqrt"), JsValue::NativeFunc(math_sqrt));
    math.insert(String::from("pow"), JsValue::NativeFunc(math_pow));
    math.insert(String::from("min"), JsValue::NativeFunc(natives::math_min));
    math.insert(String::from("max"), JsValue::NativeFunc(natives::math_max));
    JsValue::Object(Rc::new(RefCell::new(math)))
}

fn math_abs(args: &[JsValue]) -> JsValue {
    JsValue::Number(libm::fabs(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))
}
fn math_floor(args: &[JsValue]) -> JsValue {
    JsValue::Number(libm::floor(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))
}
fn math_ceil(args: &[JsValue]) -> JsValue {
    JsValue::Number(libm::ceil(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))
}
fn math_round(args: &[JsValue]) -> JsValue {
    JsValue::Number(libm::round(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))
}
fn math_sqrt(args: &[JsValue]) -> JsValue {
    JsValue::Number(libm::sqrt(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))
}
fn math_pow(args: &[JsValue]) -> JsValue {
    let base = args.get(0).map(|v| v.to_number()).unwrap_or(0.0);
    let exp = args.get(1).map(|v| v.to_number()).unwrap_or(0.0);
    JsValue::Number(libm::pow(base, exp))
}

pub(super) fn create_console() -> JsValue {
    let mut console = BTreeMap::new();
    console.insert(String::from("log"), JsValue::NativeFunc(super::natives::console_log));
    console.insert(String::from("error"), JsValue::NativeFunc(super::natives::console_log));
    console.insert(String::from("warn"), JsValue::NativeFunc(super::natives::console_log));
    JsValue::Object(Rc::new(RefCell::new(console)))
}

pub(super) fn create_json() -> JsValue {
    let mut json = BTreeMap::new();
    json.insert(String::from("stringify"), JsValue::NativeFunc(natives::json_stringify));
    json.insert(String::from("parse"), JsValue::NativeFunc(natives::json_parse));
    JsValue::Object(Rc::new(RefCell::new(json)))
}
