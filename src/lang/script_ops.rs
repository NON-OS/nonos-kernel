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

use super::script::{NoxScript, Value};
use super::script_expr::eval_expr;
use alloc::vec::Vec;

pub fn eval_binop(s: &mut NoxScript, expr: &str, op: char) -> Result<Value, &'static str> {
    let parts: Vec<&str> = expr.splitn(2, op).collect();
    if parts.len() != 2 {
        return Ok(Value::Nil);
    }
    let a = eval_expr(s, parts[0])?;
    let b = eval_expr(s, parts[1])?;
    match (a, b, op) {
        (Value::Int(a), Value::Int(b), '+') => Ok(Value::Int(a + b)),
        (Value::Int(a), Value::Int(b), '-') => Ok(Value::Int(a - b)),
        (Value::Int(a), Value::Int(b), '*') => Ok(Value::Int(a * b)),
        (Value::Int(a), Value::Int(b), '/') => {
            if b == 0 {
                Err("division by zero")
            } else {
                Ok(Value::Int(a / b))
            }
        }
        (Value::Int(a), Value::Int(b), '%') => {
            if b == 0 {
                Err("modulo by zero")
            } else {
                Ok(Value::Int(a % b))
            }
        }
        (Value::Float(a), Value::Float(b), '+') => Ok(Value::Float(a + b)),
        (Value::Float(a), Value::Float(b), '-') => Ok(Value::Float(a - b)),
        (Value::Float(a), Value::Float(b), '*') => Ok(Value::Float(a * b)),
        (Value::Float(a), Value::Float(b), '/') => Ok(Value::Float(a / b)),
        (Value::Str(a), Value::Str(b), '+') => Ok(Value::Str(a + &b)),
        _ => Ok(Value::Nil),
    }
}

pub fn eval_cmp(s: &mut NoxScript, expr: &str, op: &str) -> Result<Value, &'static str> {
    let parts: Vec<&str> = expr.splitn(2, op).collect();
    if parts.len() != 2 {
        return Ok(Value::Bool(false));
    }
    let a = eval_expr(s, parts[0])?;
    let b = eval_expr(s, parts[1])?;
    let result = match (a, b, op) {
        (Value::Int(a), Value::Int(b), "==") => a == b,
        (Value::Int(a), Value::Int(b), "!=") => a != b,
        (Value::Int(a), Value::Int(b), "<") => a < b,
        (Value::Int(a), Value::Int(b), ">") => a > b,
        (Value::Int(a), Value::Int(b), "<=") => a <= b,
        (Value::Int(a), Value::Int(b), ">=") => a >= b,
        (Value::Str(a), Value::Str(b), "==") => a == b,
        (Value::Str(a), Value::Str(b), "!=") => a != b,
        (Value::Bool(a), Value::Bool(b), "==") => a == b,
        (Value::Bool(a), Value::Bool(b), "!=") => a != b,
        _ => false,
    };
    Ok(Value::Bool(result))
}

pub fn eval_logic(s: &mut NoxScript, expr: &str, op: &str) -> Result<Value, &'static str> {
    let parts: Vec<&str> = expr.splitn(2, op).collect();
    if parts.len() != 2 {
        return Ok(Value::Bool(false));
    }
    let a = is_truthy(&eval_expr(s, parts[0])?);
    let b = is_truthy(&eval_expr(s, parts[1])?);
    Ok(Value::Bool(if op == "&&" { a && b } else { a || b }))
}

pub fn eval_not(s: &mut NoxScript, expr: &str) -> Result<Value, &'static str> {
    Ok(Value::Bool(!is_truthy(&eval_expr(s, expr)?)))
}

pub fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Nil => false,
        Value::Bool(b) => *b,
        Value::Int(i) => *i != 0,
        _ => true,
    }
}
