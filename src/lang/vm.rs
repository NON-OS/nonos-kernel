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

use super::bytecode::Bytecode;
use alloc::vec::Vec;

pub struct NoxVM {
    pub stack: Vec<i64>,
    pub locals: Vec<i64>,
    pub globals: Vec<i64>,
    pub memory: Vec<u8>,
    pub call_stack: Vec<usize>,
    pub pc: usize,
    pub running: bool,
}

impl NoxVM {
    pub fn new() -> Self {
        Self {
            stack: Vec::with_capacity(1024),
            locals: vec![0; 256],
            globals: vec![0; 256],
            memory: vec![0; 65536],
            call_stack: Vec::with_capacity(256),
            pc: 0,
            running: false,
        }
    }

    pub fn run(&mut self, bc: &Bytecode) -> Result<i64, &'static str> {
        self.pc = bc.entry as usize;
        self.running = true;
        while self.running && self.pc < bc.code.len() {
            let op = bc.code[self.pc];
            self.pc += 1;
            super::vm_ops::exec(self, op, &bc.code)?;
        }
        Ok(self.stack.pop().unwrap_or(0))
    }

    pub fn push(&mut self, v: i64) {
        self.stack.push(v);
    }
    pub fn pop(&mut self) -> Result<i64, &'static str> {
        self.stack.pop().ok_or("stack underflow")
    }
    pub fn peek(&self) -> Result<i64, &'static str> {
        self.stack.last().copied().ok_or("stack empty")
    }

    pub fn read_u8(&mut self, code: &[u8]) -> u8 {
        let v = code[self.pc];
        self.pc += 1;
        v
    }
    pub fn read_u16(&mut self, code: &[u8]) -> u16 {
        let v = u16::from_le_bytes([code[self.pc], code[self.pc + 1]]);
        self.pc += 2;
        v
    }
    pub fn read_u32(&mut self, code: &[u8]) -> u32 {
        let v = u32::from_le_bytes([
            code[self.pc],
            code[self.pc + 1],
            code[self.pc + 2],
            code[self.pc + 3],
        ]);
        self.pc += 4;
        v
    }
    pub fn read_i64(&mut self, code: &[u8]) -> i64 {
        let v = i64::from_le_bytes([
            code[self.pc],
            code[self.pc + 1],
            code[self.pc + 2],
            code[self.pc + 3],
            code[self.pc + 4],
            code[self.pc + 5],
            code[self.pc + 6],
            code[self.pc + 7],
        ]);
        self.pc += 8;
        v
    }

    pub fn mem_load(&self, addr: usize, size: usize) -> Result<i64, &'static str> {
        if addr + size > self.memory.len() {
            return Err("mem out of bounds");
        }
        let mut val = 0i64;
        for i in 0..size {
            val |= (self.memory[addr + i] as i64) << (i * 8);
        }
        Ok(val)
    }

    pub fn mem_store(&mut self, addr: usize, val: i64, size: usize) -> Result<(), &'static str> {
        if addr + size > self.memory.len() {
            return Err("mem out of bounds");
        }
        for i in 0..size {
            self.memory[addr + i] = ((val >> (i * 8)) & 0xFF) as u8;
        }
        Ok(())
    }
}
