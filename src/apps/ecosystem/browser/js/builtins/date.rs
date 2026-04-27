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

pub fn create_date_constructor() -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("now"), JsValue::NativeFunc(date_now));
    obj.insert(String::from("parse"), JsValue::NativeFunc(date_parse));
    obj.insert(String::from("UTC"), JsValue::NativeFunc(date_utc));
    obj.insert(String::from("prototype"), create_date_prototype());
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn create_date_prototype() -> JsValue {
    let mut proto = BTreeMap::new();
    proto.insert(String::from("getTime"), JsValue::NativeFunc(date_get_time));
    proto.insert(String::from("getFullYear"), JsValue::NativeFunc(date_get_full_year));
    proto.insert(String::from("getMonth"), JsValue::NativeFunc(date_get_month));
    proto.insert(String::from("getDate"), JsValue::NativeFunc(date_get_date));
    proto.insert(String::from("getDay"), JsValue::NativeFunc(date_get_day));
    proto.insert(String::from("getHours"), JsValue::NativeFunc(date_get_hours));
    proto.insert(String::from("getMinutes"), JsValue::NativeFunc(date_get_minutes));
    proto.insert(String::from("getSeconds"), JsValue::NativeFunc(date_get_seconds));
    proto.insert(String::from("getMilliseconds"), JsValue::NativeFunc(date_get_milliseconds));
    proto.insert(String::from("setTime"), JsValue::NativeFunc(date_set_time));
    proto.insert(String::from("setFullYear"), JsValue::NativeFunc(date_set_full_year));
    proto.insert(String::from("setMonth"), JsValue::NativeFunc(date_set_month));
    proto.insert(String::from("setDate"), JsValue::NativeFunc(date_set_date));
    proto.insert(String::from("setHours"), JsValue::NativeFunc(date_set_hours));
    proto.insert(String::from("setMinutes"), JsValue::NativeFunc(date_set_minutes));
    proto.insert(String::from("setSeconds"), JsValue::NativeFunc(date_set_seconds));
    proto.insert(String::from("setMilliseconds"), JsValue::NativeFunc(date_set_milliseconds));
    proto.insert(String::from("toISOString"), JsValue::NativeFunc(date_to_iso_string));
    proto.insert(String::from("toJSON"), JsValue::NativeFunc(date_to_json));
    proto.insert(String::from("toString"), JsValue::NativeFunc(date_to_string));
    proto.insert(String::from("toDateString"), JsValue::NativeFunc(date_to_date_string));
    proto.insert(String::from("toTimeString"), JsValue::NativeFunc(date_to_time_string));
    proto.insert(String::from("toLocaleString"), JsValue::NativeFunc(date_to_locale_string));
    proto.insert(String::from("valueOf"), JsValue::NativeFunc(date_value_of));
    JsValue::Object(Rc::new(RefCell::new(proto)))
}

fn date_now(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_parse(_args: &[JsValue]) -> JsValue {
    JsValue::Number(f64::NAN)
}
fn date_utc(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_get_time(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_get_full_year(_args: &[JsValue]) -> JsValue {
    JsValue::Number(2026.0)
}
fn date_get_month(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_get_date(_args: &[JsValue]) -> JsValue {
    JsValue::Number(1.0)
}
fn date_get_day(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_get_hours(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_get_minutes(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_get_seconds(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_get_milliseconds(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_set_time(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_set_full_year(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_set_month(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_set_date(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_set_hours(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_set_minutes(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_set_seconds(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_set_milliseconds(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn date_to_iso_string(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::from("2026-01-01T00:00:00.000Z"))
}
fn date_to_json(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::from("2026-01-01T00:00:00.000Z"))
}
fn date_to_string(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::from("Thu Jan 01 2026 00:00:00 GMT+0000"))
}
fn date_to_date_string(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::from("Thu Jan 01 2026"))
}
fn date_to_time_string(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::from("00:00:00 GMT+0000"))
}
fn date_to_locale_string(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::from("1/1/2026, 12:00:00 AM"))
}
fn date_value_of(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
