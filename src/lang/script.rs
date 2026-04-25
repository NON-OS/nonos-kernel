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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
}

#[derive(Clone)]
pub struct Function {
    pub params: Vec<String>,
    pub body: Vec<String>,
}

pub struct NoxScript {
    pub vars: BTreeMap<String, Value>,
    pub funcs: BTreeMap<String, Function>,
    pub call_depth: usize,
}

impl NoxScript {
    pub fn new() -> Self {
        Self { vars: BTreeMap::new(), funcs: BTreeMap::new(), call_depth: 0 }
    }

    pub fn eval(&mut self, code: &str) -> Result<Value, &'static str> {
        let lines: Vec<&str> = code.lines().collect();
        self.exec_block(&lines, 0, lines.len())
    }

    pub fn exec_block(
        &mut self,
        lines: &[&str],
        start: usize,
        end: usize,
    ) -> Result<Value, &'static str> {
        let mut i = start;
        let mut last = Value::Nil;
        while i < end {
            let line = lines[i].trim();
            if line.is_empty() || line.starts_with('#') {
                i += 1;
                continue;
            }
            if line.starts_with("if ") {
                let (val, skip) = super::script_control::exec_if(self, lines, i)?;
                last = val;
                i += skip;
            } else if line.starts_with("while ") {
                let (val, skip) = super::script_control::exec_while(self, lines, i)?;
                last = val;
                i += skip;
            } else if line.starts_with("fn ") {
                i += super::script_control::parse_fn(self, lines, i)?;
            } else if line.starts_with("return ") {
                return super::script_expr::eval_expr(self, &line[7..]);
            } else {
                last = self.exec_line(line)?;
                i += 1;
            }
        }
        Ok(last)
    }

    pub fn exec_line(&mut self, line: &str) -> Result<Value, &'static str> {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        match parts.get(0).copied() {
            Some("let") => super::script_expr::parse_let(self, parts.get(1).unwrap_or(&"")),
            Some("print") => super::script_expr::parse_print(self, parts.get(1).unwrap_or(&"")),
            Some(name) if self.funcs.contains_key(name) => {
                super::script_control::call_fn(self, line)
            }
            Some(name) if self.vars.contains_key(name) => {
                Ok(self.vars.get(name).cloned().unwrap_or(Value::Nil))
            }
            _ => super::script_expr::eval_expr(self, line),
        }
    }
}
