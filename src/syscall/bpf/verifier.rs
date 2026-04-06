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

pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_RET: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;
pub const BPF_EXIT: u8 = 0x95;

pub struct BpfVerifier;

impl BpfVerifier {
    pub fn verify(insns: &[u64]) -> Result<(), i32> {
        if insns.is_empty() {
            return Err(22);
        }
        let mut has_exit = false;
        for (i, insn) in insns.iter().enumerate() {
            let opcode = (*insn & 0xFF) as u8;
            let class = opcode & 0x07;
            match class {
                BPF_LD | BPF_LDX | BPF_ST | BPF_STX | BPF_ALU | BPF_ALU64 => {}
                BPF_JMP => {
                    if opcode == BPF_EXIT {
                        has_exit = true;
                    } else {
                        let off = ((*insn >> 16) & 0xFFFF) as i16;
                        let target = i as i32 + 1 + off as i32;
                        if target < 0 || target >= insns.len() as i32 {
                            return Err(22);
                        }
                    }
                }
                BPF_RET => has_exit = true,
                _ => return Err(22),
            }
        }
        if !has_exit {
            return Err(22);
        }
        Ok(())
    }

    pub fn check_bounds(_insns: &[u64], _pc: usize) -> bool {
        true
    }
}
