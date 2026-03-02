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
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuContext {
    // Callee-saved registers
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,

    // Control/entry state
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,

    // Segment selectors used when transitioning to user mode (if applicable).
    pub cs: u64,
    pub ss: u64,
}

impl CpuContext {
    #[inline]
    pub const fn new() -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            rbp: 0,
            rip: 0,
            rsp: 0,
            rflags: 0,
            cs: 0,
            ss: 0,
        }
    }

    #[inline]
    pub fn prepare_user_entry(
        &mut self,
        entry: u64,
        user_stack_top: u64,
        user_cs: u64,
        user_ss: u64,
        rflags: u64,
    ) {
        self.rip = entry;
        self.rsp = user_stack_top;
        self.cs = user_cs;
        self.ss = user_ss;
        self.rflags = rflags | 1 << 1; // Bit 1 must be set on x86_64
    }

    #[inline]
    pub fn prepare_kernel_entry(&mut self, entry: u64, kernel_stack_top: u64, rflags: u64) {
        self.rip = entry;
        self.rsp = kernel_stack_top;
        self.cs = 0;
        self.ss = 0;
        self.rflags = rflags | 1 << 1; // reserved bit set
    }
}
