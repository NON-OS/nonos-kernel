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
use super::value::JsValue;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn console_log(args: &[JsValue]) -> JsValue {
    let _msg: Vec<String> = args.iter().map(|v| v.to_string()).collect();
    JsValue::Undefined
}

pub(super) fn parse_int(args: &[JsValue]) -> JsValue {
    let s = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    JsValue::Number(s.trim().parse::<i64>().map(|n| n as f64).unwrap_or(f64::NAN))
}

pub(super) fn parse_float(args: &[JsValue]) -> JsValue {
    let s = args.get(0).map(|v| v.to_string()).unwrap_or_default();
    JsValue::Number(s.trim().parse().unwrap_or(f64::NAN))
}

pub(super) fn is_nan(args: &[JsValue]) -> JsValue {
    JsValue::Bool(args.get(0).map(|v| v.to_number().is_nan()).unwrap_or(true))
}

pub(super) fn is_finite(args: &[JsValue]) -> JsValue {
    JsValue::Bool(args.get(0).map(|v| v.to_number().is_finite()).unwrap_or(false))
}

pub(super) fn math_min(args: &[JsValue]) -> JsValue {
    if args.is_empty() {
        return JsValue::Number(f64::INFINITY);
    }
    let mut m = f64::INFINITY;
    for a in args {
        let n = a.to_number();
        if n < m {
            m = n;
        }
    }
    JsValue::Number(m)
}

pub(super) fn math_max(args: &[JsValue]) -> JsValue {
    if args.is_empty() {
        return JsValue::Number(f64::NEG_INFINITY);
    }
    let mut m = f64::NEG_INFINITY;
    for a in args {
        let n = a.to_number();
        if n > m {
            m = n;
        }
    }
    JsValue::Number(m)
}

pub(super) fn json_stringify(args: &[JsValue]) -> JsValue {
    JsValue::String(args.get(0).map(|v| v.to_string()).unwrap_or_default())
}

pub(super) fn json_parse(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
