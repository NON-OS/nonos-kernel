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
use super::value::JsValue;
use super::engine::JsRuntime;
use crate::apps::ecosystem::browser::js::parser::{Expr, Literal, UnaryOp, BinaryOp, LogicalOp, AssignOp};

impl JsRuntime {
    pub fn eval_unary(&mut self, op: UnaryOp, arg: &Expr, prefix: bool) -> JsValue {
        let v = self.eval_expr(arg);
        match op {
            UnaryOp::Minus => JsValue::Number(-v.to_number()),
            UnaryOp::Plus => JsValue::Number(v.to_number()),
            UnaryOp::Not => JsValue::Bool(!v.to_bool()),
            UnaryOp::BitNot => JsValue::Number(!((v.to_number() as i32)) as f64),
            UnaryOp::Typeof => JsValue::String(String::from(v.type_of())),
            UnaryOp::Void => JsValue::Undefined,
            UnaryOp::PrefixInc | UnaryOp::PostfixInc => { let n = v.to_number(); if let Expr::Ident(name) = arg { self.scope.set(name, JsValue::Number(n + 1.0)); } if prefix { JsValue::Number(n + 1.0) } else { JsValue::Number(n) } }
            UnaryOp::PrefixDec | UnaryOp::PostfixDec => { let n = v.to_number(); if let Expr::Ident(name) = arg { self.scope.set(name, JsValue::Number(n - 1.0)); } if prefix { JsValue::Number(n - 1.0) } else { JsValue::Number(n) } }
            _ => JsValue::Undefined,
        }
    }
    pub fn eval_binary(&mut self, op: BinaryOp, left: &Expr, right: &Expr) -> JsValue {
        let l = self.eval_expr(left);
        let r = self.eval_expr(right);
        match op {
            BinaryOp::Add => { if matches!(l, JsValue::String(_)) || matches!(r, JsValue::String(_)) { JsValue::String(alloc::format!("{}{}", l.to_string(), r.to_string())) } else { JsValue::Number(l.to_number() + r.to_number()) } }
            BinaryOp::Sub => JsValue::Number(l.to_number() - r.to_number()),
            BinaryOp::Mul => JsValue::Number(l.to_number() * r.to_number()),
            BinaryOp::Div => JsValue::Number(l.to_number() / r.to_number()),
            BinaryOp::Mod => JsValue::Number(l.to_number() % r.to_number()),
            BinaryOp::Pow => JsValue::Number(libm::pow(l.to_number(), r.to_number())),
            BinaryOp::BitAnd => JsValue::Number(((l.to_number() as i32) & (r.to_number() as i32)) as f64),
            BinaryOp::BitOr => JsValue::Number(((l.to_number() as i32) | (r.to_number() as i32)) as f64),
            BinaryOp::BitXor => JsValue::Number(((l.to_number() as i32) ^ (r.to_number() as i32)) as f64),
            BinaryOp::Shl => JsValue::Number(((l.to_number() as i32) << (r.to_number() as u32 & 0x1f)) as f64),
            BinaryOp::Shr => JsValue::Number(((l.to_number() as i32) >> (r.to_number() as u32 & 0x1f)) as f64),
            BinaryOp::Ushr => JsValue::Number(((l.to_number() as u32) >> (r.to_number() as u32 & 0x1f)) as f64),
            BinaryOp::Lt => JsValue::Bool(l.to_number() < r.to_number()),
            BinaryOp::Le => JsValue::Bool(l.to_number() <= r.to_number()),
            BinaryOp::Gt => JsValue::Bool(l.to_number() > r.to_number()),
            BinaryOp::Ge => JsValue::Bool(l.to_number() >= r.to_number()),
            BinaryOp::Eq | BinaryOp::StrictEq => self.eq_check(&l, &r, op == BinaryOp::StrictEq),
            BinaryOp::Ne | BinaryOp::StrictNe => { let eq = self.eq_check(&l, &r, op == BinaryOp::StrictNe); JsValue::Bool(!eq.to_bool()) }
            BinaryOp::Instanceof => JsValue::Bool(matches!((&l, &r), (JsValue::Object(_), JsValue::Function(_) | JsValue::NativeFunc(_)))),
            BinaryOp::In => { if let JsValue::Object(ref o) = r { let key = l.to_string(); JsValue::Bool(o.borrow().contains_key(&key)) } else { JsValue::Bool(false) } }
        }
    }
    fn eq_check(&self, l: &JsValue, r: &JsValue, strict: bool) -> JsValue {
        if strict { JsValue::Bool(match (l, r) { (JsValue::Undefined, JsValue::Undefined) | (JsValue::Null, JsValue::Null) => true, (JsValue::Bool(a), JsValue::Bool(b)) => a == b, (JsValue::Number(a), JsValue::Number(b)) => a == b, (JsValue::String(a), JsValue::String(b)) => a == b, _ => false }) }
        else { JsValue::Bool(match (l, r) { (JsValue::Undefined, JsValue::Null) | (JsValue::Null, JsValue::Undefined) => true, (JsValue::Number(a), JsValue::Number(b)) => a == b, (JsValue::String(a), JsValue::String(b)) => a == b, (JsValue::Bool(a), JsValue::Bool(b)) => a == b, _ => l.to_number() == r.to_number() }) }
    }
    pub fn eval_logical(&mut self, op: LogicalOp, left: &Expr, right: &Expr) -> JsValue {
        let l = self.eval_expr(left);
        match op { LogicalOp::And => if !l.to_bool() { l } else { self.eval_expr(right) }, LogicalOp::Or => if l.to_bool() { l } else { self.eval_expr(right) }, LogicalOp::NullishCoalesce => if matches!(l, JsValue::Null | JsValue::Undefined) { self.eval_expr(right) } else { l } }
    }
    pub fn eval_assign(&mut self, op: AssignOp, left: &Expr, right: &Expr) -> JsValue {
        let r = self.eval_expr(right);
        let val = match op { AssignOp::Assign => r.clone(), AssignOp::AddAssign => { let l = self.eval_expr(left); if matches!(l, JsValue::String(_)) { JsValue::String(alloc::format!("{}{}", l.to_string(), r.to_string())) } else { JsValue::Number(l.to_number() + r.to_number()) } }, AssignOp::SubAssign => JsValue::Number(self.eval_expr(left).to_number() - r.to_number()), AssignOp::MulAssign => JsValue::Number(self.eval_expr(left).to_number() * r.to_number()), AssignOp::DivAssign => JsValue::Number(self.eval_expr(left).to_number() / r.to_number()), _ => r.clone() };
        if let Expr::Ident(name) = left { self.scope.set(name, val.clone()); }
        if let Expr::Member { obj, prop, computed } = left { let o = self.eval_expr(obj); let key = if *computed { self.eval_expr(prop).to_string() } else { if let Expr::Literal(Literal::String(s)) = prop.as_ref() { s.clone() } else { String::new() } }; if let JsValue::Object(ref ob) = o { ob.borrow_mut().insert(key.clone(), val.clone()); } if let JsValue::Array(ref a) = o { if let Ok(i) = key.parse::<usize>() { let mut arr = a.borrow_mut(); if i >= arr.len() { arr.resize(i + 1, JsValue::Undefined); } arr[i] = val.clone(); } } }
        val
    }
}
