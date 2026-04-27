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
use super::types::Value;
use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_WHITE};
use crate::shell::output::print_line;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub fn builtin_echo(args: &[Value]) {
    let s: String = args.iter().map(|v| val_to_str(v)).collect::<Vec<_>>().join(" ");
    print_line(s.as_bytes(), COLOR_WHITE);
}

pub fn builtin_print(args: &[Value]) {
    for a in args {
        print_line(val_to_str(a).as_bytes(), COLOR_GREEN);
    }
}

pub fn builtin_len(args: &[Value]) -> Value {
    if let Some(v) = args.first() {
        match v {
            Value::Str(s) => Value::Num(s.len() as i64),
            Value::List(l) => Value::Num(l.len() as i64),
            _ => Value::Num(0),
        }
    } else {
        Value::Num(0)
    }
}

pub fn builtin_type(args: &[Value]) -> Value {
    if let Some(v) = args.first() {
        Value::Str(
            match v {
                Value::Num(_) => "number",
                Value::Str(_) => "string",
                Value::Bool(_) => "boolean",
                Value::List(_) => "list",
                Value::None => "none",
            }
            .into(),
        )
    } else {
        Value::Str("none".into())
    }
}

pub fn builtin_int(args: &[Value]) -> Value {
    if let Some(v) = args.first() {
        match v {
            Value::Num(n) => Value::Num(*n),
            Value::Str(s) => Value::Num(s.parse().unwrap_or(0)),
            Value::Bool(b) => Value::Num(if *b { 1 } else { 0 }),
            _ => Value::Num(0),
        }
    } else {
        Value::Num(0)
    }
}

pub fn builtin_str(args: &[Value]) -> Value {
    if let Some(v) = args.first() {
        Value::Str(val_to_str(v))
    } else {
        Value::Str(String::new())
    }
}

fn val_to_str(v: &Value) -> String {
    match v {
        Value::Num(n) => n.to_string(),
        Value::Str(s) => s.clone(),
        Value::Bool(b) => (if *b { "true" } else { "false" }).into(),
        Value::List(l) => {
            let s: Vec<_> = l.iter().map(val_to_str).collect();
            alloc::format!("[{}]", s.join(", "))
        }
        Value::None => String::new(),
    }
}
