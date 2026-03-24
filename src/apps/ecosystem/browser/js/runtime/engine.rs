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
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use super::value::JsValue;
use super::scope::Scope;
use crate::apps::ecosystem::browser::js::parser::Parser;

pub struct JsRuntime { pub scope: Scope, pub this: JsValue, pub return_val: Option<JsValue>, pub break_flag: bool, pub continue_flag: bool }

impl JsRuntime {
    pub fn new() -> Self {
        let mut rt = Self { scope: Scope::new(), this: JsValue::Undefined, return_val: None, break_flag: false, continue_flag: false };
        rt.init_globals();
        rt
    }
    fn init_globals(&mut self) {
        self.scope.declare(String::from("undefined"), JsValue::Undefined);
        self.scope.declare(String::from("NaN"), JsValue::Number(f64::NAN));
        self.scope.declare(String::from("Infinity"), JsValue::Number(f64::INFINITY));
        self.scope.declare(String::from("console"), self.create_console());
        self.scope.declare(String::from("Math"), self.create_math());
        self.scope.declare(String::from("JSON"), self.create_json());
        self.scope.declare(String::from("parseInt"), JsValue::NativeFunc(native_parse_int));
        self.scope.declare(String::from("parseFloat"), JsValue::NativeFunc(native_parse_float));
        self.scope.declare(String::from("isNaN"), JsValue::NativeFunc(native_is_nan));
        self.scope.declare(String::from("isFinite"), JsValue::NativeFunc(native_is_finite));
    }
    fn create_console(&self) -> JsValue {
        let obj: BTreeMap<String, JsValue> = BTreeMap::new();
        let console = Rc::new(RefCell::new(obj));
        console.borrow_mut().insert(String::from("log"), JsValue::NativeFunc(native_console_log));
        console.borrow_mut().insert(String::from("error"), JsValue::NativeFunc(native_console_log));
        console.borrow_mut().insert(String::from("warn"), JsValue::NativeFunc(native_console_log));
        JsValue::Object(console)
    }
    fn create_math(&self) -> JsValue {
        let obj: BTreeMap<String, JsValue> = BTreeMap::new();
        let math = Rc::new(RefCell::new(obj));
        math.borrow_mut().insert(String::from("PI"), JsValue::Number(core::f64::consts::PI));
        math.borrow_mut().insert(String::from("E"), JsValue::Number(core::f64::consts::E));
        math.borrow_mut().insert(String::from("abs"), JsValue::NativeFunc(|args| JsValue::Number(libm::fabs(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))));
        math.borrow_mut().insert(String::from("floor"), JsValue::NativeFunc(|args| JsValue::Number(libm::floor(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))));
        math.borrow_mut().insert(String::from("ceil"), JsValue::NativeFunc(|args| JsValue::Number(libm::ceil(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))));
        math.borrow_mut().insert(String::from("round"), JsValue::NativeFunc(|args| JsValue::Number(libm::round(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))));
        math.borrow_mut().insert(String::from("sqrt"), JsValue::NativeFunc(|args| JsValue::Number(libm::sqrt(args.get(0).map(|v| v.to_number()).unwrap_or(f64::NAN)))));
        math.borrow_mut().insert(String::from("pow"), JsValue::NativeFunc(|args| JsValue::Number(libm::pow(args.get(0).map(|v| v.to_number()).unwrap_or(0.0), args.get(1).map(|v| v.to_number()).unwrap_or(0.0)))));
        math.borrow_mut().insert(String::from("min"), JsValue::NativeFunc(native_math_min));
        math.borrow_mut().insert(String::from("max"), JsValue::NativeFunc(native_math_max));
        JsValue::Object(math)
    }
    fn create_json(&self) -> JsValue {
        let obj: BTreeMap<String, JsValue> = BTreeMap::new();
        let json = Rc::new(RefCell::new(obj));
        json.borrow_mut().insert(String::from("stringify"), JsValue::NativeFunc(native_json_stringify));
        json.borrow_mut().insert(String::from("parse"), JsValue::NativeFunc(native_json_parse));
        JsValue::Object(json)
    }
    pub fn execute(&mut self, src: &str) -> JsValue {
        let program = Parser::new(src).parse();
        let mut result = JsValue::Undefined;
        for stmt in program.body { result = self.eval_stmt(&stmt); if self.return_val.is_some() { break; } }
        self.return_val.take().unwrap_or(result)
    }
}

fn native_console_log(args: &[JsValue]) -> JsValue { let _msg: Vec<String> = args.iter().map(|v| v.to_string()).collect(); JsValue::Undefined }
fn native_parse_int(args: &[JsValue]) -> JsValue { let s = args.get(0).map(|v| v.to_string()).unwrap_or_default(); JsValue::Number(s.trim().parse::<i64>().map(|n| n as f64).unwrap_or(f64::NAN)) }
fn native_parse_float(args: &[JsValue]) -> JsValue { let s = args.get(0).map(|v| v.to_string()).unwrap_or_default(); JsValue::Number(s.trim().parse().unwrap_or(f64::NAN)) }
fn native_is_nan(args: &[JsValue]) -> JsValue { JsValue::Bool(args.get(0).map(|v| v.to_number().is_nan()).unwrap_or(true)) }
fn native_is_finite(args: &[JsValue]) -> JsValue { JsValue::Bool(args.get(0).map(|v| v.to_number().is_finite()).unwrap_or(false)) }
fn native_math_min(args: &[JsValue]) -> JsValue { if args.is_empty() { return JsValue::Number(f64::INFINITY); } let mut m = f64::INFINITY; for a in args { let n = a.to_number(); if n < m { m = n; } } JsValue::Number(m) }
fn native_math_max(args: &[JsValue]) -> JsValue { if args.is_empty() { return JsValue::Number(f64::NEG_INFINITY); } let mut m = f64::NEG_INFINITY; for a in args { let n = a.to_number(); if n > m { m = n; } } JsValue::Number(m) }
fn native_json_stringify(args: &[JsValue]) -> JsValue { JsValue::String(args.get(0).map(|v| v.to_string()).unwrap_or_default()) }
fn native_json_parse(_args: &[JsValue]) -> JsValue { JsValue::Undefined }
