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

use super::types::{SeccompData, SockFilter, SECCOMP_RET_ALLOW};
use alloc::vec::Vec;

pub const BPF_LD: u16 = 0x00;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_K: u16 = 0x00;

#[derive(Clone)]
pub struct SeccompFilter {
    pub instructions: Vec<SockFilter>,
    pub flags: u32,
}

impl SeccompFilter {
    pub fn new(instructions: Vec<SockFilter>, flags: u32) -> Self {
        Self { instructions, flags }
    }

    pub fn validate(&self) -> Result<(), i32> {
        if self.instructions.is_empty() {
            return Err(22);
        }
        if self.instructions.len() > 4096 {
            return Err(22);
        }
        for (i, insn) in self.instructions.iter().enumerate() {
            if !Self::validate_instruction(insn, i, self.instructions.len()) {
                return Err(22);
            }
        }
        Ok(())
    }

    fn validate_instruction(insn: &SockFilter, idx: usize, len: usize) -> bool {
        let class = insn.code & 0x07;
        match class {
            0x05 => {
                let jt_target = idx + 1 + insn.jt as usize;
                let jf_target = idx + 1 + insn.jf as usize;
                jt_target <= len && jf_target <= len
            }
            0x06 => true,
            0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x07 => true,
            _ => false,
        }
    }

    pub fn run(&self, data: &SeccompData) -> u32 {
        let mut a: u32 = 0;
        let mut pc: usize = 0;
        let data_bytes = unsafe { core::slice::from_raw_parts(data as *const _ as *const u8, 64) };
        while pc < self.instructions.len() {
            let insn = &self.instructions[pc];
            let class = insn.code & 0x07;
            match class {
                0x00 => {
                    if insn.code & 0x60 == BPF_ABS && (insn.k as usize) < data_bytes.len() {
                        a = u32::from_ne_bytes([
                            data_bytes[insn.k as usize],
                            data_bytes.get(insn.k as usize + 1).copied().unwrap_or(0),
                            data_bytes.get(insn.k as usize + 2).copied().unwrap_or(0),
                            data_bytes.get(insn.k as usize + 3).copied().unwrap_or(0),
                        ]);
                    }
                    pc += 1;
                }
                0x05 => {
                    if insn.code & 0xf0 == BPF_JEQ {
                        pc += 1 + if a == insn.k { insn.jt as usize } else { insn.jf as usize };
                    } else {
                        pc += 1;
                    }
                }
                0x06 => return insn.k,
                _ => {
                    pc += 1;
                }
            }
        }
        SECCOMP_RET_ALLOW
    }
}
