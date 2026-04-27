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
use super::script_ops::{eval_binop, eval_cmp, eval_logic, eval_not};
use alloc::{string::ToString, vec::Vec};

pub fn parse_let(s: &mut NoxScript, rest: &str) -> Result<Value, &'static str> {
    let parts: Vec<&str> = rest.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err("syntax: let x = value");
    }
    let name = parts[0].trim().to_string();
    let val = eval_expr(s, parts[1].trim())?;
    s.vars.insert(name, val.clone());
    Ok(val)
}

pub fn parse_print(s: &mut NoxScript, rest: &str) -> Result<Value, &'static str> {
    let val = eval_expr(s, rest)?;
    let out = match &val {
        Value::Int(i) => alloc::format!("{}", i),
        Value::Float(f) => alloc::format!("{}", f),
        Value::Str(t) => t.clone(),
        Value::Bool(b) => {
            if *b {
                "true".into()
            } else {
                "false".into()
            }
        }
        Value::Nil => "nil".into(),
        Value::List(l) => alloc::format!("[{} items]", l.len()),
    };
    crate::shell::output::print_line(out.as_bytes(), 0xFFFFFFFF);
    Ok(val)
}

pub fn eval_expr(s: &mut NoxScript, expr: &str) -> Result<Value, &'static str> {
    let expr = expr.trim();
    if expr == "true" {
        return Ok(Value::Bool(true));
    }
    if expr == "false" {
        return Ok(Value::Bool(false));
    }
    if expr == "nil" {
        return Ok(Value::Nil);
    }
    if expr.starts_with('"') && expr.ends_with('"') && expr.len() > 1 {
        return Ok(Value::Str(expr[1..expr.len() - 1].to_string()));
    }
    if let Ok(i) = expr.parse::<i64>() {
        return Ok(Value::Int(i));
    }
    if let Ok(f) = expr.parse::<f64>() {
        return Ok(Value::Float(f));
    }
    if let Some(v) = s.vars.get(expr) {
        return Ok(v.clone());
    }
    if expr.contains("==") {
        return eval_cmp(s, expr, "==");
    }
    if expr.contains("!=") {
        return eval_cmp(s, expr, "!=");
    }
    if expr.contains(">=") {
        return eval_cmp(s, expr, ">=");
    }
    if expr.contains("<=") {
        return eval_cmp(s, expr, "<=");
    }
    if expr.contains('>') {
        return eval_cmp(s, expr, ">");
    }
    if expr.contains('<') {
        return eval_cmp(s, expr, "<");
    }
    if expr.contains("&&") {
        return eval_logic(s, expr, "&&");
    }
    if expr.contains("||") {
        return eval_logic(s, expr, "||");
    }
    if expr.contains('+') {
        return eval_binop(s, expr, '+');
    }
    if expr.contains('-') && !expr.starts_with('-') {
        return eval_binop(s, expr, '-');
    }
    if expr.contains('*') {
        return eval_binop(s, expr, '*');
    }
    if expr.contains('/') {
        return eval_binop(s, expr, '/');
    }
    if expr.contains('%') {
        return eval_binop(s, expr, '%');
    }
    if expr.starts_with('!') {
        return eval_not(s, &expr[1..]);
    }
    if expr.contains('(') {
        return super::script_control::call_fn(s, expr);
    }
    Ok(Value::Nil)
}
