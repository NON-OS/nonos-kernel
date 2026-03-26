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
use super::value::{JsValue, JsFuncInner};
use super::engine::JsRuntime;
use crate::apps::ecosystem::browser::js::parser::{Expr, Literal};

impl JsRuntime {
    pub fn eval_expr(&mut self, expr: &Expr) -> JsValue {
        match expr {
            Expr::Literal(lit) => match lit { Literal::Null => JsValue::Null, Literal::Undefined => JsValue::Undefined, Literal::Bool(b) => JsValue::Bool(*b), Literal::Number(n) => JsValue::Number(*n), Literal::String(s) => JsValue::String(s.clone()), _ => JsValue::Undefined },
            Expr::Ident(name) => self.scope.get(name),
            Expr::This => self.this.clone(),
            Expr::Array(elems) => { let arr: Vec<JsValue> = elems.iter().map(|e| e.as_ref().map(|ex| self.eval_expr(ex)).unwrap_or(JsValue::Undefined)).collect(); JsValue::Array(Rc::new(RefCell::new(arr))) }
            Expr::Object(props) => { let mut obj = BTreeMap::new(); for p in props { let key = match &p.key { Expr::Literal(Literal::String(s)) => s.clone(), Expr::Ident(s) => s.clone(), _ => self.eval_expr(&p.key).to_string() }; obj.insert(key, self.eval_expr(&p.value)); } JsValue::Object(Rc::new(RefCell::new(obj))) }
            Expr::Member { obj, prop, computed } => { let o = self.eval_expr(obj); let key = if *computed { self.eval_expr(prop).to_string() } else { if let Expr::Literal(Literal::String(s)) = prop.as_ref() { s.clone() } else { self.eval_expr(prop).to_string() } }; self.get_member(&o, &key) }
            Expr::Call { callee, args } => self.call_func(callee, args),
            Expr::New { callee, args } => self.call_new(callee, args),
            Expr::Unary { op, arg, prefix } => self.eval_unary(*op, arg, *prefix),
            Expr::Binary { op, left, right } => self.eval_binary(*op, left, right),
            Expr::Logical { op, left, right } => self.eval_logical(*op, left, right),
            Expr::Conditional { test, consequent, alternate } => { if self.eval_expr(test).to_bool() { self.eval_expr(consequent) } else { self.eval_expr(alternate) } }
            Expr::Assign { op, left, right } => self.eval_assign(*op, left, right),
            Expr::Sequence(exprs) => { let mut r = JsValue::Undefined; for e in exprs { r = self.eval_expr(e); } r }
            Expr::Function { name, params, body, .. } => JsValue::Function(Rc::new(JsFuncInner { name: name.clone(), params: params.clone(), body: body.clone() })),
            _ => JsValue::Undefined,
        }
    }
    fn get_member(&self, obj: &JsValue, key: &str) -> JsValue {
        match obj {
            JsValue::Object(o) => o.borrow().get(key).cloned().unwrap_or(JsValue::Undefined),
            JsValue::Array(a) => { if key == "length" { JsValue::Number(a.borrow().len() as f64) } else if let Ok(i) = key.parse::<usize>() { a.borrow().get(i).cloned().unwrap_or(JsValue::Undefined) } else { JsValue::Undefined } }
            JsValue::String(s) => { if key == "length" { JsValue::Number(s.len() as f64) } else if let Ok(i) = key.parse::<usize>() { s.chars().nth(i).map(|c| JsValue::String(alloc::format!("{}", c))).unwrap_or(JsValue::Undefined) } else { JsValue::Undefined } }
            _ => JsValue::Undefined,
        }
    }
    fn call_func(&mut self, callee: &Expr, args: &[Expr]) -> JsValue {
        let func = self.eval_expr(callee);
        let arg_vals: Vec<JsValue> = args.iter().map(|a| self.eval_expr(a)).collect();
        match func {
            JsValue::NativeFunc(f) => f(&arg_vals),
            JsValue::Function(f) => { self.scope.push(); for (i, p) in f.params.iter().enumerate() { self.scope.declare(p.clone(), arg_vals.get(i).cloned().unwrap_or(JsValue::Undefined)); } self.eval_stmt(&f.body); self.scope.pop(); self.return_val.take().unwrap_or(JsValue::Undefined) }
            JsValue::Object(o) => { if let Expr::Member { obj: _, prop, computed } = callee { let key = if *computed { self.eval_expr(prop).to_string() } else { if let Expr::Literal(Literal::String(s)) = prop.as_ref() { s.clone() } else { String::new() } }; if let Some(JsValue::NativeFunc(f)) = o.borrow().get(&key) { return f(&arg_vals); } } JsValue::Undefined }
            _ => JsValue::Undefined,
        }
    }
    fn call_new(&mut self, callee: &Expr, args: &[Expr]) -> JsValue {
        let func = self.eval_expr(callee);
        let arg_vals: Vec<JsValue> = args.iter().map(|a| self.eval_expr(a)).collect();
        match func {
            JsValue::Function(f) => { let obj = Rc::new(RefCell::new(BTreeMap::new())); let old_this = core::mem::replace(&mut self.this, JsValue::Object(obj.clone())); self.scope.push(); for (i, p) in f.params.iter().enumerate() { self.scope.declare(p.clone(), arg_vals.get(i).cloned().unwrap_or(JsValue::Undefined)); } self.eval_stmt(&f.body); self.scope.pop(); self.return_val.take(); self.this = old_this; JsValue::Object(obj) }
            _ => JsValue::Object(Rc::new(RefCell::new(BTreeMap::new()))),
        }
    }
}
