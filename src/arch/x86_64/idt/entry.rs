// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::arch::x86_64::idt::constants::*;

pub trait FnPtr {
    fn addr(self) -> u64;
}

impl<T> FnPtr for T
where
    T: Copy,
{
    #[inline]
    fn addr(self) -> u64 {
        let ptr = &self as *const T as *const ();
        // SAFETY: Reading the function pointer address from a properly aligned pointer.
        unsafe { core::ptr::read(ptr as *const u64) }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    pub const fn empty() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    pub fn interrupt_gate<F>(handler: F, selector: u16, ist: u8, dpl: u8) -> Self
    where
        F: FnPtr,
    {
        let addr = handler.addr();
        Self {
            offset_low: (addr & 0xFFFF) as u16,
            selector,
            ist: ist & 0x7,
            type_attr: PRESENT | ((dpl & 0x3) << 5) | GATE_INTERRUPT,
            offset_mid: ((addr >> 16) & 0xFFFF) as u16,
            offset_high: (addr >> 32) as u32,
            reserved: 0,
        }
    }

    pub fn trap_gate<F>(handler: F, selector: u16, ist: u8, dpl: u8) -> Self
    where
        F: FnPtr,
    {
        let addr = handler.addr();
        Self {
            offset_low: (addr & 0xFFFF) as u16,
            selector,
            ist: ist & 0x7,
            type_attr: PRESENT | ((dpl & 0x3) << 5) | GATE_TRAP,
            offset_mid: ((addr >> 16) & 0xFFFF) as u16,
            offset_high: (addr >> 32) as u32,
            reserved: 0,
        }
    }

    pub fn is_present(&self) -> bool {
        self.type_attr & PRESENT != 0
    }

    pub fn handler(&self) -> u64 {
        (self.offset_low as u64)
            | ((self.offset_mid as u64) << 16)
            | ((self.offset_high as u64) << 32)
    }

    pub fn ist(&self) -> u8 {
        self.ist & 0x7
    }

    pub fn dpl(&self) -> u8 {
        (self.type_attr >> 5) & 0x3
    }

    pub fn is_trap(&self) -> bool {
        (self.type_attr & 0xF) == GATE_TRAP
    }

    pub fn set_handler(&mut self, handler: u64) {
        self.offset_low = (handler & 0xFFFF) as u16;
        self.offset_mid = ((handler >> 16) & 0xFFFF) as u16;
        self.offset_high = (handler >> 32) as u32;
    }

    pub fn set_ist(&mut self, ist: u8) {
        self.ist = ist & 0x7;
    }

    pub fn set_dpl(&mut self, dpl: u8) {
        self.type_attr = (self.type_attr & !0x60) | ((dpl & 0x3) << 5);
    }
}

impl core::fmt::Debug for IdtEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let selector = self.selector;
        f.debug_struct("IdtEntry")
            .field("handler", &format_args!("{:#x}", self.handler()))
            .field("selector", &format_args!("{:#x}", selector))
            .field("ist", &self.ist())
            .field("dpl", &self.dpl())
            .field("present", &self.is_present())
            .field("trap", &self.is_trap())
            .finish()
    }
}

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

pub type ExceptionHandler = extern "C" fn(&mut InterruptFrame);
pub type ExceptionHandlerWithError = extern "C" fn(&mut InterruptFrame, error_code: u64);
