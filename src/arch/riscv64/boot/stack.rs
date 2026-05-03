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

use core::arch::asm;

pub const KERNEL_STACK_SIZE: usize = 32768;
pub const IRQ_STACK_SIZE: usize = 8192;

#[repr(C, align(16))]
pub struct KernelStack {
    data: [u8; KERNEL_STACK_SIZE],
}

impl KernelStack {
    pub const fn new() -> Self {
        Self { data: [0; KERNEL_STACK_SIZE] }
    }

    pub fn top(&self) -> u64 {
        let ptr = self.data.as_ptr();
        (ptr as u64) + KERNEL_STACK_SIZE as u64
    }
}

#[repr(C, align(16))]
pub struct IrqStack {
    data: [u8; IRQ_STACK_SIZE],
}

impl IrqStack {
    pub const fn new() -> Self {
        Self { data: [0; IRQ_STACK_SIZE] }
    }

    pub fn top(&self) -> u64 {
        let ptr = self.data.as_ptr();
        (ptr as u64) + IRQ_STACK_SIZE as u64
    }
}

static mut KERNEL_STACKS: [KernelStack; 64] = [const { KernelStack::new() }; 64];
static mut IRQ_STACKS: [IrqStack; 64] = [const { IrqStack::new() }; 64];

pub fn setup_stack(hart_id: usize) {
    let kernel_top = unsafe { KERNEL_STACKS[hart_id].top() };

    unsafe {
        asm!(
            "mv sp, {0}",
            in(reg) kernel_top,
            options(nostack)
        );
    }
}

pub fn get_kernel_stack(hart_id: usize) -> u64 {
    unsafe { KERNEL_STACKS[hart_id].top() }
}

pub fn get_irq_stack(hart_id: usize) -> u64 {
    unsafe { IRQ_STACKS[hart_id].top() }
}

pub fn current_stack_pointer() -> u64 {
    let sp: u64;
    unsafe {
        asm!("mv {}, sp", out(reg) sp, options(nostack));
    }
    sp
}

pub fn stack_remaining(hart_id: usize) -> usize {
    let sp = current_stack_pointer();
    let base = unsafe { KERNEL_STACKS[hart_id].data.as_ptr() as u64 };
    (sp - base) as usize
}
