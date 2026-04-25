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

use super::bytecode::{Bytecode, Op};
use alloc::string::String;
use alloc::vec::Vec;

pub struct Compiler {
    bc: Bytecode,
    locals: Vec<String>,
}

impl Compiler {
    pub fn new() -> Self {
        Self { bc: Bytecode::new(), locals: Vec::new() }
    }

    pub fn compile(&mut self, source: &str) -> Result<Bytecode, &'static str> {
        for line in source.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.compile_line(line)?;
        }
        self.bc.emit(Op::Halt);
        Ok(self.bc.clone())
    }

    fn compile_line(&mut self, line: &str) -> Result<(), &'static str> {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        match parts.get(0).copied() {
            Some("let") => self.compile_let(parts.get(1).unwrap_or(&"")),
            Some("print") => self.compile_print(parts.get(1).unwrap_or(&"")),
            Some("return") => {
                self.compile_expr(parts.get(1).unwrap_or(&"0"))?;
                self.bc.emit(Op::Ret);
                Ok(())
            }
            _ => self.compile_expr(line),
        }
    }

    fn compile_let(&mut self, rest: &str) -> Result<(), &'static str> {
        let parts: Vec<&str> = rest.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err("syntax");
        }
        let name = parts[0].trim();
        self.compile_expr(parts[1].trim())?;
        let idx = self.locals.len();
        self.locals.push(name.into());
        self.bc.emit(Op::StoreLocal);
        self.bc.code.push(idx as u8);
        Ok(())
    }

    fn compile_print(&mut self, expr: &str) -> Result<(), &'static str> {
        self.compile_expr(expr)?;
        self.bc.emit(Op::Print);
        Ok(())
    }

    fn compile_expr(&mut self, expr: &str) -> Result<(), &'static str> {
        let expr = expr.trim();
        if let Ok(i) = expr.parse::<i64>() {
            self.bc.emit(Op::Push);
            self.bc.emit_i64(i);
            return Ok(());
        }
        if let Some(idx) = self.locals.iter().position(|n| n == expr) {
            self.bc.emit(Op::LoadLocal);
            self.bc.code.push(idx as u8);
            return Ok(());
        }
        if expr.contains('+') {
            return self.compile_binop(expr, '+', Op::Add);
        }
        if expr.contains('-') {
            return self.compile_binop(expr, '-', Op::Sub);
        }
        if expr.contains('*') {
            return self.compile_binop(expr, '*', Op::Mul);
        }
        self.bc.emit(Op::Push);
        self.bc.emit_i64(0);
        Ok(())
    }

    fn compile_binop(&mut self, expr: &str, sep: char, op: Op) -> Result<(), &'static str> {
        let parts: Vec<&str> = expr.splitn(2, sep).collect();
        if parts.len() != 2 {
            return Ok(());
        }
        self.compile_expr(parts[0])?;
        self.compile_expr(parts[1])?;
        self.bc.emit(op);
        Ok(())
    }
}
