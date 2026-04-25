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

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Op {
    Nop = 0x00,
    Halt = 0x01,
    Push = 0x10,
    Pop = 0x11,
    Dup = 0x12,
    Swap = 0x13,
    LoadLocal = 0x20,
    StoreLocal = 0x21,
    LoadGlobal = 0x22,
    StoreGlobal = 0x23,
    Add = 0x30,
    Sub = 0x31,
    Mul = 0x32,
    Div = 0x33,
    Mod = 0x34,
    Neg = 0x35,
    And = 0x40,
    Or = 0x41,
    Xor = 0x42,
    Not = 0x43,
    Shl = 0x44,
    Shr = 0x45,
    Eq = 0x50,
    Ne = 0x51,
    Lt = 0x52,
    Le = 0x53,
    Gt = 0x54,
    Ge = 0x55,
    Jmp = 0x60,
    JmpIf = 0x61,
    JmpIfNot = 0x62,
    Call = 0x70,
    Ret = 0x71,
    CallNative = 0x72,
    Alloc = 0x80,
    Free = 0x81,
    Load = 0x82,
    Store = 0x83,
    Print = 0x90,
    Read = 0x91,
    Syscall = 0x92,
}

#[derive(Clone)]
pub struct Bytecode {
    pub magic: [u8; 4],
    pub version: u16,
    pub entry: u32,
    pub code: alloc::vec::Vec<u8>,
    pub data: alloc::vec::Vec<u8>,
    pub symbols: alloc::vec::Vec<Symbol>,
}

#[derive(Clone)]
pub struct Symbol {
    pub name: [u8; 32],
    pub offset: u32,
    pub kind: u8,
}

impl Bytecode {
    pub const MAGIC: [u8; 4] = *b"NOXB";

    pub fn new() -> Self {
        Self {
            magic: Self::MAGIC,
            version: 1,
            entry: 0,
            code: alloc::vec::Vec::new(),
            data: alloc::vec::Vec::new(),
            symbols: alloc::vec::Vec::new(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 || &data[0..4] != &Self::MAGIC {
            return None;
        }
        let version = u16::from_le_bytes([data[4], data[5]]);
        let entry = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
        let code_len = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
        if data.len() < 14 + code_len {
            return None;
        }
        let code = data[14..14 + code_len].to_vec();
        Some(Self {
            magic: Self::MAGIC,
            version,
            entry,
            code,
            data: alloc::vec::Vec::new(),
            symbols: alloc::vec::Vec::new(),
        })
    }

    pub fn emit(&mut self, op: Op) {
        self.code.push(op as u8);
    }
    pub fn emit_u32(&mut self, v: u32) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }
    pub fn emit_i64(&mut self, v: i64) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }
}
