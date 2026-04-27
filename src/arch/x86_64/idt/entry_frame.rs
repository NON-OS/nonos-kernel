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
#[derive(Debug, Clone, Copy)]
pub struct InterruptFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl InterruptFrame {
    pub fn from_user(&self) -> bool {
        (self.cs & 0x3) == 3
    }
    pub fn from_kernel(&self) -> bool {
        (self.cs & 0x3) == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PageFaultError(pub u64);

impl PageFaultError {
    pub fn protection_violation(self) -> bool {
        self.0 & (1 << 0) != 0
    }
    pub fn write(self) -> bool {
        self.0 & (1 << 1) != 0
    }
    pub fn user(self) -> bool {
        self.0 & (1 << 2) != 0
    }
    pub fn reserved_write(self) -> bool {
        self.0 & (1 << 3) != 0
    }
    pub fn instruction_fetch(self) -> bool {
        self.0 & (1 << 4) != 0
    }
    pub fn protection_key(self) -> bool {
        self.0 & (1 << 5) != 0
    }
    pub fn shadow_stack(self) -> bool {
        self.0 & (1 << 6) != 0
    }
    pub fn sgx(self) -> bool {
        self.0 & (1 << 15) != 0
    }
}
