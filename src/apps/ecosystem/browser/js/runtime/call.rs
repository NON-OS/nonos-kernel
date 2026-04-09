extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use super::value::JsValue;
use super::engine::JsRuntime;
use crate::apps::ecosystem::browser::js::parser::{Expr, Literal};

impl JsRuntime {
    pub fn call_func(&mut self, callee: &Expr, args: &[Expr]) -> JsValue {
        let arg_vals: Vec<JsValue> = args.iter().map(|a| self.eval_expr(a)).collect();
        if let Expr::Member { obj, prop, computed } = callee {
            let receiver = self.eval_expr(obj);
            let key = self.resolve_key(prop, *computed);
            return self.call_method(receiver, &key, &arg_vals);
        }
        if let Expr::Ident(name) = callee {
            if let Some(r) = self.dispatch_builtin(name, &arg_vals) { return r; }
        }
        let func = self.eval_expr(callee);
        self.invoke_value(&func, &arg_vals)
    }

    pub fn call_new(&mut self, callee: &Expr, args: &[Expr]) -> JsValue {
        let func = self.eval_expr(callee);
        let arg_vals: Vec<JsValue> = args.iter().map(|a| self.eval_expr(a)).collect();
        match func {
            JsValue::NativeFunc(f) => f(&arg_vals),
            JsValue::Function(f) => {
                let obj = Rc::new(RefCell::new(BTreeMap::new()));
                let old_this = core::mem::replace(&mut self.this, JsValue::Object(obj.clone()));
                self.scope.push();
                for (i, p) in f.params.iter().enumerate() {
                    self.scope.declare(p.clone(), arg_vals.get(i).cloned().unwrap_or(JsValue::Undefined));
                }
                self.eval_stmt(&f.body);
                self.scope.pop();
                self.return_val.take();
                self.this = old_this;
                JsValue::Object(obj)
            }
            _ => JsValue::Object(Rc::new(RefCell::new(BTreeMap::new()))),
        }
    }

    fn call_method(&mut self, receiver: JsValue, key: &str, args: &[JsValue]) -> JsValue {
        if let JsValue::Array(ref arr) = receiver {
            if let Some(r) = self.array_callback(arr, key, args) { return r; }
        }
        let method = self.get_member(&receiver, key);
        match method {
            JsValue::NativeFunc(f) => {
                let mut full_args = alloc::vec![receiver];
                full_args.extend_from_slice(args);
                f(&full_args)
            }
            JsValue::Function(f) => {
                let old_this = core::mem::replace(&mut self.this, receiver);
                self.scope.push();
                for (i, p) in f.params.iter().enumerate() {
                    self.scope.declare(p.clone(), args.get(i).cloned().unwrap_or(JsValue::Undefined));
                }
                self.eval_stmt(&f.body);
                self.scope.pop();
                self.this = old_this;
                self.return_val.take().unwrap_or(JsValue::Undefined)
            }
            _ => JsValue::Undefined,
        }
    }

    pub fn invoke_value(&mut self, func: &JsValue, args: &[JsValue]) -> JsValue {
        match func {
            JsValue::NativeFunc(f) => f(args),
            JsValue::Function(f) => {
                self.scope.push();
                for (i, p) in f.params.iter().enumerate() {
                    self.scope.declare(p.clone(), args.get(i).cloned().unwrap_or(JsValue::Undefined));
                }
                self.eval_stmt(&f.body);
                self.scope.pop();
                self.return_val.take().unwrap_or(JsValue::Undefined)
            }
            _ => JsValue::Undefined,
        }
    }

    pub(super) fn resolve_key(&mut self, prop: &Expr, computed: bool) -> String {
        if computed { self.eval_expr(prop).to_string() }
        else if let Expr::Literal(Literal::String(s)) = prop { s.clone() }
        else { self.eval_expr(prop).to_string() }
    }
}
