extern crate alloc;
use super::engine::JsRuntime;
use super::value::{JsFuncInner, JsValue};
use crate::apps::ecosystem::browser::js::parser::{ArrowBody, Expr, Literal, Stmt, TemplateLit};
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

impl JsRuntime {
    pub fn eval_expr(&mut self, expr: &Expr) -> JsValue {
        match expr {
            Expr::Literal(lit) => match lit {
                Literal::Null => JsValue::Null,
                Literal::Undefined => JsValue::Undefined,
                Literal::Bool(b) => JsValue::Bool(*b),
                Literal::Number(n) => JsValue::Number(*n),
                Literal::String(s) => JsValue::String(s.clone()),
                _ => JsValue::Undefined,
            },
            Expr::Ident(name) => self.scope.get(name),
            Expr::This => self.this.clone(),
            Expr::Array(elems) => {
                let arr: Vec<JsValue> = elems
                    .iter()
                    .map(|e| e.as_ref().map(|ex| self.eval_expr(ex)).unwrap_or(JsValue::Undefined))
                    .collect();
                JsValue::Array(Rc::new(RefCell::new(arr)))
            }
            Expr::Object(props) => {
                let mut obj = BTreeMap::new();
                for p in props {
                    let key = match &p.key {
                        Expr::Literal(Literal::String(s)) => s.clone(),
                        Expr::Ident(s) => s.clone(),
                        _ => self.eval_expr(&p.key).to_string(),
                    };
                    obj.insert(key, self.eval_expr(&p.value));
                }
                JsValue::Object(Rc::new(RefCell::new(obj)))
            }
            Expr::Member { obj, prop, computed } => {
                let o = self.eval_expr(obj);
                let key = self.resolve_key(prop, *computed);
                self.get_member(&o, &key)
            }
            Expr::Call { callee, args } => self.call_func(callee, args),
            Expr::New { callee, args } => self.call_new(callee, args),
            Expr::Unary { op, arg, prefix } => self.eval_unary(*op, arg, *prefix),
            Expr::Binary { op, left, right } => self.eval_binary(*op, left, right),
            Expr::Logical { op, left, right } => self.eval_logical(*op, left, right),
            Expr::Conditional { test, consequent, alternate } => {
                if self.eval_expr(test).to_bool() {
                    self.eval_expr(consequent)
                } else {
                    self.eval_expr(alternate)
                }
            }
            Expr::Assign { op, left, right } => self.eval_assign(*op, left, right),
            Expr::Sequence(exprs) => {
                let mut r = JsValue::Undefined;
                for e in exprs {
                    r = self.eval_expr(e);
                }
                r
            }
            Expr::Function { name, params, body, .. } => JsValue::Function(Rc::new(JsFuncInner {
                name: name.clone(),
                params: params.clone(),
                body: body.clone(),
            })),
            Expr::Arrow { params, body, .. } => self.eval_arrow(params, body),
            Expr::Template(lit) => self.eval_template(lit),
            Expr::Spread(inner) => self.eval_expr(inner),
            _ => JsValue::Undefined,
        }
    }

    fn eval_arrow(&mut self, params: &[String], body: &ArrowBody) -> JsValue {
        match body {
            ArrowBody::Expr(expr) => {
                let ret_stmt = Stmt::Return(Some((**expr).clone()));
                JsValue::Function(Rc::new(JsFuncInner {
                    name: None,
                    params: params.to_vec(),
                    body: alloc::boxed::Box::new(ret_stmt),
                }))
            }
            ArrowBody::Block(stmt) => JsValue::Function(Rc::new(JsFuncInner {
                name: None,
                params: params.to_vec(),
                body: stmt.clone(),
            })),
        }
    }

    fn eval_template(&mut self, lit: &TemplateLit) -> JsValue {
        let mut result = String::new();
        for (i, quasi) in lit.quasis.iter().enumerate() {
            result.push_str(quasi);
            if let Some(expr) = lit.exprs.get(i) {
                result.push_str(&self.eval_expr(expr).to_string());
            }
        }
        JsValue::String(result)
    }
}
