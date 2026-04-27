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

use super::vm::NoxVM;

pub fn exec(vm: &mut NoxVM, op: u8, code: &[u8]) -> Result<(), &'static str> {
    match op {
        0x00 => {}
        0x01 => vm.running = false,
        0x10 => {
            let v = vm.read_i64(code);
            vm.push(v);
        }
        0x11 => {
            vm.pop()?;
        }
        0x12 => {
            let v = vm.peek()?;
            vm.push(v);
        }
        0x13 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(b);
            vm.push(a);
        }
        0x20 => {
            let i = vm.read_u8(code) as usize;
            vm.push(vm.locals[i]);
        }
        0x21 => {
            let i = vm.read_u8(code) as usize;
            vm.locals[i] = vm.pop()?;
        }
        0x22 => {
            let i = vm.read_u8(code) as usize;
            vm.push(vm.globals[i]);
        }
        0x23 => {
            let i = vm.read_u8(code) as usize;
            vm.globals[i] = vm.pop()?;
        }
        0x30 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(a.wrapping_add(b));
        }
        0x31 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(a.wrapping_sub(b));
        }
        0x32 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(a.wrapping_mul(b));
        }
        0x33 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            if b == 0 {
                return Err("div by zero");
            }
            vm.push(a / b);
        }
        0x34 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            if b == 0 {
                return Err("mod by zero");
            }
            vm.push(a % b);
        }
        0x35 => {
            let a = vm.pop()?;
            vm.push(-a);
        }
        0x40 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(a & b);
        }
        0x41 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(a | b);
        }
        0x42 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(a ^ b);
        }
        0x43 => {
            let a = vm.pop()?;
            vm.push(!a);
        }
        0x44 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(a << (b & 63));
        }
        0x45 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(a >> (b & 63));
        }
        0x50 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(if a == b { 1 } else { 0 });
        }
        0x51 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(if a != b { 1 } else { 0 });
        }
        0x52 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(if a < b { 1 } else { 0 });
        }
        0x53 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(if a <= b { 1 } else { 0 });
        }
        0x54 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(if a > b { 1 } else { 0 });
        }
        0x55 => {
            let b = vm.pop()?;
            let a = vm.pop()?;
            vm.push(if a >= b { 1 } else { 0 });
        }
        0x60 => {
            vm.pc = vm.read_u32(code) as usize;
        }
        0x61 => {
            let addr = vm.read_u32(code) as usize;
            if vm.pop()? != 0 {
                vm.pc = addr;
            }
        }
        0x62 => {
            let addr = vm.read_u32(code) as usize;
            if vm.pop()? == 0 {
                vm.pc = addr;
            }
        }
        0x70 => {
            let addr = vm.read_u32(code) as usize;
            vm.call_stack.push(vm.pc);
            vm.pc = addr;
        }
        0x71 => {
            if let Some(ret) = vm.call_stack.pop() {
                vm.pc = ret;
            } else {
                vm.running = false;
            }
        }
        0x82 => {
            let addr = vm.pop()? as usize;
            let size = vm.read_u8(code) as usize;
            vm.push(vm.mem_load(addr, size)?);
        }
        0x83 => {
            let val = vm.pop()?;
            let addr = vm.pop()? as usize;
            let size = vm.read_u8(code) as usize;
            vm.mem_store(addr, val, size)?;
        }
        0x90 => {
            let v = vm.pop()?;
            crate::shell::output::print_line(alloc::format!("{}", v).as_bytes(), 0xFFFFFFFF);
        }
        _ => {}
    }
    Ok(())
}
