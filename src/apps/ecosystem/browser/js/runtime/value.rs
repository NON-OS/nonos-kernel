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
use crate::apps::ecosystem::browser::js::parser::Stmt;
use crate::apps::ecosystem::browser::js::promise::JsPromise;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

pub(super) type JsObject = Rc<RefCell<BTreeMap<String, JsValue>>>;
pub(super) type JsArray = Rc<RefCell<Vec<JsValue>>>;
pub(super) type JsFunc = Rc<JsFuncInner>;

#[derive(Clone)]
pub struct JsFuncInner {
    pub name: Option<String>,
    pub params: Vec<String>,
    pub body: alloc::boxed::Box<Stmt>,
}

#[derive(Clone)]
pub enum JsValue {
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Object(JsObject),
    Array(JsArray),
    Function(JsFunc),
    NativeFunc(fn(&[JsValue]) -> JsValue),
    Promise(JsPromise),
}

impl core::fmt::Debug for JsValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Undefined => write!(f, "Undefined"),
            Self::Null => write!(f, "Null"),
            Self::Bool(b) => write!(f, "Bool({})", b),
            Self::Number(n) => write!(f, "Number({})", n),
            Self::String(s) => write!(f, "String(\"{}\")", s),
            Self::Object(_) => write!(f, "Object"),
            Self::Array(_) => write!(f, "Array"),
            Self::Function(_) => write!(f, "Function"),
            Self::NativeFunc(_) => write!(f, "NativeFunc"),
            Self::Promise(_) => write!(f, "Promise"),
        }
    }
}

impl JsValue {
    pub fn to_bool(&self) -> bool {
        match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(b) => *b,
            Self::Number(n) => *n != 0.0 && !n.is_nan(),
            Self::String(s) => !s.is_empty(),
            _ => true,
        }
    }
    pub fn to_number(&self) -> f64 {
        match self {
            Self::Undefined => f64::NAN,
            Self::Null => 0.0,
            Self::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            Self::Number(n) => *n,
            Self::String(s) => s.parse().unwrap_or(f64::NAN),
            _ => f64::NAN,
        }
    }
    pub fn to_string(&self) -> String {
        match self {
            Self::Undefined => String::from("undefined"),
            Self::Null => String::from("null"),
            Self::Bool(b) => {
                if *b {
                    String::from("true")
                } else {
                    String::from("false")
                }
            }
            Self::Number(n) => {
                if n.is_nan() {
                    String::from("NaN")
                } else if n.is_infinite() {
                    if *n > 0.0 {
                        String::from("Infinity")
                    } else {
                        String::from("-Infinity")
                    }
                } else {
                    alloc::format!("{}", n)
                }
            }
            Self::String(s) => s.clone(),
            Self::Object(_) => String::from("[object Object]"),
            Self::Array(a) => {
                let arr = a.borrow();
                let parts: Vec<String> = arr.iter().map(|v| v.to_string()).collect();
                parts.join(",")
            }
            Self::Function(_) | Self::NativeFunc(_) => String::from("[Function]"),
            Self::Promise(_) => String::from("[object Promise]"),
        }
    }
    pub fn type_of(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null => "object",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Object(_) | Self::Array(_) | Self::Promise(_) => "object",
            Self::Function(_) | Self::NativeFunc(_) => "function",
        }
    }
}
