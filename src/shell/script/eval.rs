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
use super::types::{BinOp, Expr, Stmt, UnaryOp, Value};
use crate::shell::commands::dispatch::dispatch;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

pub struct Env {
    vars: BTreeMap<String, Value>,
    fns: BTreeMap<String, (Vec<String>, Vec<Stmt>)>,
}
impl Env {
    pub fn new() -> Self {
        Self { vars: BTreeMap::new(), fns: BTreeMap::new() }
    }
    pub fn get(&self, k: &str) -> Value {
        self.vars.get(k).cloned().unwrap_or(Value::None)
    }
    pub fn set(&mut self, k: String, v: Value) {
        self.vars.insert(k, v);
    }
}

pub fn execute(stmts: &[Stmt]) {
    let mut env = Env::new();
    for s in stmts {
        exec_stmt(s, &mut env);
    }
}

fn exec_stmt(stmt: &Stmt, env: &mut Env) -> Option<Value> {
    match stmt {
        Stmt::Assign { name, value } => {
            env.set(name.clone(), eval_expr(value, env));
            None
        }
        Stmt::If { cond, then_block, else_block } => {
            let b = if eval_expr(cond, env).is_truthy() { then_block } else { else_block };
            for s in b {
                if let Some(r) = exec_stmt(s, env) {
                    return Some(r);
                }
            }
            None
        }
        Stmt::For { var, items, body } => {
            for i in items {
                env.set(var.clone(), eval_expr(i, env));
                for s in body {
                    if let Some(r) = exec_stmt(s, env) {
                        return Some(r);
                    }
                }
            }
            None
        }
        Stmt::While { cond, body } => {
            while eval_expr(cond, env).is_truthy() {
                for s in body {
                    if let Some(r) = exec_stmt(s, env) {
                        return Some(r);
                    }
                }
            }
            None
        }
        Stmt::Fn { name, params, body } => {
            env.fns.insert(name.clone(), (params.clone(), body.clone()));
            None
        }
        Stmt::Return { value } => {
            Some(value.as_ref().map(|e| eval_expr(e, env)).unwrap_or(Value::None))
        }
        Stmt::Cmd { name, args } => {
            exec_cmd(name, &args.iter().map(|e| val_str(&eval_expr(e, env))).collect::<Vec<_>>());
            None
        }
        Stmt::Expr(e) => {
            eval_expr(e, env);
            None
        }
    }
}

fn eval_expr(e: &Expr, env: &Env) -> Value {
    match e {
        Expr::Num(n) => Value::Num(*n),
        Expr::Str(s) => Value::Str(s.clone()),
        Expr::Bool(b) => Value::Bool(*b),
        Expr::Var(n) => env.get(n),
        Expr::BinOp { op, left, right } => binop(op, eval_expr(left, env), eval_expr(right, env)),
        Expr::UnaryOp { op, expr } => {
            let v = eval_expr(expr, env);
            match op {
                UnaryOp::Not => Value::Bool(!v.is_truthy()),
                UnaryOp::Neg => {
                    if let Value::Num(n) = v {
                        Value::Num(-n)
                    } else {
                        Value::Num(0)
                    }
                }
            }
        }
        Expr::Call { .. } => Value::None,
        Expr::List(i) => Value::List(i.iter().map(|x| eval_expr(x, env)).collect()),
    }
}

fn binop(op: &BinOp, l: Value, r: Value) -> Value {
    match op {
        BinOp::Add => {
            if let (Value::Num(a), Value::Num(b)) = (&l, &r) {
                Value::Num(a + b)
            } else {
                Value::Str(val_str(&l) + &val_str(&r))
            }
        }
        BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
            let (a, b) = (num(&l), num(&r));
            match op {
                BinOp::Sub => Value::Num(a - b),
                BinOp::Mul => Value::Num(a * b),
                BinOp::Div => Value::Num(if b != 0 { a / b } else { 0 }),
                BinOp::Mod => Value::Num(if b != 0 { a % b } else { 0 }),
                _ => Value::Num(0),
            }
        }
        BinOp::Eq => Value::Bool(val_str(&l) == val_str(&r)),
        BinOp::Ne => Value::Bool(val_str(&l) != val_str(&r)),
        BinOp::Lt => Value::Bool(num(&l) < num(&r)),
        BinOp::Gt => Value::Bool(num(&l) > num(&r)),
        BinOp::Le => Value::Bool(num(&l) <= num(&r)),
        BinOp::Ge => Value::Bool(num(&l) >= num(&r)),
        BinOp::And => Value::Bool(l.is_truthy() && r.is_truthy()),
        BinOp::Or => Value::Bool(l.is_truthy() || r.is_truthy()),
    }
}

fn num(v: &Value) -> i64 {
    if let Value::Num(n) = v {
        *n
    } else {
        0
    }
}
fn val_str(v: &Value) -> String {
    match v {
        Value::Num(n) => n.to_string(),
        Value::Str(s) => s.clone(),
        Value::Bool(b) => (if *b { "true" } else { "false" }).into(),
        _ => String::new(),
    }
}
fn exec_cmd(name: &str, args: &[String]) {
    let mut c = name.as_bytes().to_vec();
    for a in args {
        c.push(b' ');
        c.extend_from_slice(a.as_bytes());
    }
    dispatch(&c);
}
