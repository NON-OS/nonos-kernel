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

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TrapFrame {
    pub ra: usize,
    pub sp: usize,
    pub gp: usize,
    pub tp: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub s0: usize,
    pub s1: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    pub sepc: usize,
    pub sstatus: usize,
    pub scause: usize,
    pub stval: usize,
}

impl TrapFrame {
    pub const fn new() -> Self {
        Self {
            ra: 0,
            sp: 0,
            gp: 0,
            tp: 0,
            t0: 0,
            t1: 0,
            t2: 0,
            s0: 0,
            s1: 0,
            a0: 0,
            a1: 0,
            a2: 0,
            a3: 0,
            a4: 0,
            a5: 0,
            a6: 0,
            a7: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
            t3: 0,
            t4: 0,
            t5: 0,
            t6: 0,
            sepc: 0,
            sstatus: 0,
            scause: 0,
            stval: 0,
        }
    }

    pub fn is_interrupt(&self) -> bool {
        (self.scause >> 63) != 0
    }

    pub fn exception_code(&self) -> usize {
        self.scause & ((1 << 63) - 1)
    }

    pub fn is_from_user(&self) -> bool {
        (self.sstatus & (1 << 8)) == 0
    }

    pub fn return_address(&self) -> usize {
        self.sepc
    }

    pub fn faulting_address(&self) -> usize {
        self.stval
    }

    pub fn set_return_value(&mut self, value: usize) {
        self.a0 = value;
    }

    pub fn syscall_number(&self) -> usize {
        self.a7
    }

    pub fn syscall_arg(&self, n: usize) -> usize {
        match n {
            0 => self.a0,
            1 => self.a1,
            2 => self.a2,
            3 => self.a3,
            4 => self.a4,
            5 => self.a5,
            _ => 0,
        }
    }

    pub fn advance_pc(&mut self) {
        self.sepc += 4;
    }

    pub fn dump(&self) {
        crate::sys::serial::println(b"Trap Frame:");
        crate::sys::serial::print(b"  sepc: ");
        crate::sys::serial::print_hex(self.sepc as u64);
        crate::sys::serial::print(b" scause: ");
        crate::sys::serial::print_hex(self.scause as u64);
        crate::sys::serial::println(b"");
        crate::sys::serial::print(b"  stval: ");
        crate::sys::serial::print_hex(self.stval as u64);
        crate::sys::serial::print(b" sp: ");
        crate::sys::serial::print_hex(self.sp as u64);
        crate::sys::serial::println(b"");
    }
}

pub const FRAME_SIZE: usize = core::mem::size_of::<TrapFrame>();
