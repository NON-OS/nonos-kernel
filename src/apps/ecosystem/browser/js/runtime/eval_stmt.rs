extern crate alloc;
use super::engine::JsRuntime;
use super::value::{JsFuncInner, JsValue};
use crate::apps::ecosystem::browser::js::parser::Stmt;
use alloc::rc::Rc;

impl JsRuntime {
    pub fn eval_stmt(&mut self, stmt: &Stmt) -> JsValue {
        if self.thrown.is_some() {
            return JsValue::Undefined;
        }
        match stmt {
            Stmt::Expr(e) => self.eval_expr(e),
            Stmt::Block(stmts) => {
                self.scope.push();
                let mut r = JsValue::Undefined;
                for s in stmts {
                    r = self.eval_stmt(s);
                    if self.return_val.is_some()
                        || self.break_flag
                        || self.continue_flag
                        || self.thrown.is_some()
                    {
                        break;
                    }
                }
                self.scope.pop();
                r
            }
            Stmt::Empty => JsValue::Undefined,
            Stmt::Var { decls, .. } => {
                for d in decls {
                    let val =
                        d.init.as_ref().map(|e| self.eval_expr(e)).unwrap_or(JsValue::Undefined);
                    self.scope.declare(d.name.clone(), val);
                }
                JsValue::Undefined
            }
            Stmt::If { cond, then_br, else_br } => {
                if self.eval_expr(cond).to_bool() {
                    self.eval_stmt(then_br)
                } else if let Some(eb) = else_br {
                    self.eval_stmt(eb)
                } else {
                    JsValue::Undefined
                }
            }
            Stmt::While { cond, body } => {
                while self.eval_expr(cond).to_bool() {
                    self.eval_stmt(body);
                    if self.break_flag {
                        self.break_flag = false;
                        break;
                    }
                    if self.continue_flag {
                        self.continue_flag = false;
                    }
                    if self.return_val.is_some() || self.thrown.is_some() {
                        break;
                    }
                }
                JsValue::Undefined
            }
            Stmt::DoWhile { body, cond } => {
                loop {
                    self.eval_stmt(body);
                    if self.break_flag {
                        self.break_flag = false;
                        break;
                    }
                    if self.continue_flag {
                        self.continue_flag = false;
                    }
                    if self.return_val.is_some() || self.thrown.is_some() {
                        break;
                    }
                    if !self.eval_expr(cond).to_bool() {
                        break;
                    }
                }
                JsValue::Undefined
            }
            Stmt::For { init, cond, update, body } => {
                self.scope.push();
                if let Some(i) = init {
                    self.eval_stmt(i);
                }
                while cond.as_ref().map(|c| self.eval_expr(c).to_bool()).unwrap_or(true) {
                    self.eval_stmt(body);
                    if self.break_flag {
                        self.break_flag = false;
                        break;
                    }
                    if self.continue_flag {
                        self.continue_flag = false;
                    }
                    if self.return_val.is_some() || self.thrown.is_some() {
                        break;
                    }
                    if let Some(u) = update {
                        self.eval_expr(u);
                    }
                }
                self.scope.pop();
                JsValue::Undefined
            }
            Stmt::Break(_) => {
                self.break_flag = true;
                JsValue::Undefined
            }
            Stmt::Continue(_) => {
                self.continue_flag = true;
                JsValue::Undefined
            }
            Stmt::Return(e) => {
                self.return_val =
                    Some(e.as_ref().map(|ex| self.eval_expr(ex)).unwrap_or(JsValue::Undefined));
                JsValue::Undefined
            }
            Stmt::Throw(e) => {
                self.thrown = Some(self.eval_expr(e));
                JsValue::Undefined
            }
            Stmt::Try { block, catch, finally } => {
                self.eval_stmt(block);
                if let Some(thrown_val) = self.thrown.take() {
                    if let Some(c) = catch {
                        self.scope.push();
                        if let Some(ref param) = c.param {
                            self.scope.declare(param.clone(), thrown_val);
                        }
                        self.eval_stmt(&c.body);
                        self.scope.pop();
                    }
                }
                if let Some(f) = finally {
                    self.eval_stmt(f);
                }
                JsValue::Undefined
            }
            Stmt::Function { name, params, body, .. } => {
                let func = JsValue::Function(Rc::new(JsFuncInner {
                    name: name.clone(),
                    params: params.clone(),
                    body: body.clone(),
                }));
                if let Some(n) = name {
                    self.scope.declare(n.clone(), func.clone());
                }
                func
            }
            Stmt::Switch { discrim, cases } => {
                let val = self.eval_expr(discrim);
                let mut matched = false;
                for c in cases {
                    if !matched {
                        if let Some(test) = &c.test {
                            let test_val = self.eval_expr(test);
                            if self.strict_eq(&val, &test_val) {
                                matched = true;
                            }
                        } else {
                            matched = true;
                        }
                    }
                    if matched {
                        for s in &c.body {
                            self.eval_stmt(s);
                            if self.break_flag {
                                self.break_flag = false;
                                return JsValue::Undefined;
                            }
                        }
                    }
                }
                JsValue::Undefined
            }
            _ => JsValue::Undefined,
        }
    }

    fn strict_eq(&self, a: &JsValue, b: &JsValue) -> bool {
        match (a, b) {
            (JsValue::Undefined, JsValue::Undefined) | (JsValue::Null, JsValue::Null) => true,
            (JsValue::Bool(x), JsValue::Bool(y)) => x == y,
            (JsValue::Number(x), JsValue::Number(y)) => x == y,
            (JsValue::String(x), JsValue::String(y)) => x == y,
            _ => false,
        }
    }
}
