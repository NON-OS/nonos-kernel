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

use super::script::{Function, NoxScript, Value};
use super::script_expr::eval_expr;
use super::script_ops::is_truthy;
use super::script_parse::find_block_end;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

pub fn exec_if(
    s: &mut NoxScript,
    lines: &[&str],
    start: usize,
) -> Result<(Value, usize), &'static str> {
    let line = lines[start].trim();
    let cond = &line[3..].trim_end_matches(':');
    let is_true = is_truthy(&eval_expr(s, cond)?);
    let (body_end, else_start) = find_block_end(lines, start);
    let result = if is_true {
        s.exec_block(lines, start + 1, body_end)?
    } else if else_start > 0 {
        let (else_end, _) = find_block_end(lines, else_start);
        s.exec_block(lines, else_start + 1, else_end)?
    } else {
        Value::Nil
    };
    let skip = if else_start > 0 {
        let (e, _) = find_block_end(lines, else_start);
        e - start + 1
    } else {
        body_end - start + 1
    };
    Ok((result, skip))
}

pub fn exec_while(
    s: &mut NoxScript,
    lines: &[&str],
    start: usize,
) -> Result<(Value, usize), &'static str> {
    let line = lines[start].trim();
    let cond = &line[6..].trim_end_matches(':');
    let (body_end, _) = find_block_end(lines, start);
    let mut last = Value::Nil;
    let mut iters = 0;
    while is_truthy(&eval_expr(s, cond)?) {
        last = s.exec_block(lines, start + 1, body_end)?;
        iters += 1;
        if iters > 10000 {
            return Err("infinite loop");
        }
    }
    Ok((last, body_end - start + 1))
}

pub fn parse_fn(s: &mut NoxScript, lines: &[&str], start: usize) -> Result<usize, &'static str> {
    let line = lines[start].trim();
    let sig = &line[3..].trim_end_matches(':');
    let paren = sig.find('(').ok_or("fn syntax")?;
    let name = sig[..paren].trim().to_string();
    let params_str = sig[paren + 1..].trim_end_matches(')');
    let params: Vec<String> = if params_str.is_empty() {
        Vec::new()
    } else {
        params_str.split(',').map(|p| p.trim().to_string()).collect()
    };
    let (body_end, _) = find_block_end(lines, start);
    let body: Vec<String> = lines[start + 1..body_end].iter().map(|l| l.to_string()).collect();
    s.funcs.insert(name, Function { params, body });
    Ok(body_end - start + 1)
}

pub fn call_fn(s: &mut NoxScript, expr: &str) -> Result<Value, &'static str> {
    let paren = expr.find('(').ok_or("call syntax")?;
    let name = expr[..paren].trim();
    let args_str = expr[paren + 1..].trim_end_matches(')');
    let func = s.funcs.get(name).ok_or("undefined function")?.clone();
    if s.call_depth > 100 {
        return Err("stack overflow");
    }
    let args: Vec<Value> = if args_str.is_empty() {
        Vec::new()
    } else {
        args_str.split(',').map(|a| eval_expr(s, a.trim()).unwrap_or(Value::Nil)).collect()
    };
    let old_vars = s.vars.clone();
    for (i, p) in func.params.iter().enumerate() {
        s.vars.insert(p.clone(), args.get(i).cloned().unwrap_or(Value::Nil));
    }
    s.call_depth += 1;
    let body_lines: Vec<&str> = func.body.iter().map(|l| l.as_str()).collect();
    let result = s.exec_block(&body_lines, 0, body_lines.len());
    s.call_depth -= 1;
    s.vars = old_vars;
    result
}
