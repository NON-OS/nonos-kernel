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

use core::ptr::null;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

use crate::arch::x86_64::idt::constants::IDT_ENTRIES;
use crate::arch::x86_64::idt::entry::InterruptFrame;
use crate::arch::x86_64::idt::table::Idt;

pub(crate) static mut IDT: Idt = Idt::new();

pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static INITIALIZING: AtomicBool = AtomicBool::new(false);

pub(crate) static INTERRUPT_COUNTS: [AtomicU64; IDT_ENTRIES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; IDT_ENTRIES]
};

pub(crate) static TOTAL_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static EXCEPTION_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static IRQ_COUNT: AtomicU64 = AtomicU64::new(0);

pub(crate) static IRQ_HANDLERS: [AtomicPtr<()>; 16] = {
    const INIT: AtomicPtr<()> = AtomicPtr::new(null::<()>() as *mut ());
    [INIT; 16]
};
pub(crate) static SYSCALL_HANDLER: AtomicPtr<()> = AtomicPtr::new(null::<()>() as *mut ());
pub(crate) static OTHER_HANDLERS: [AtomicPtr<()>; 256] = {
    const INIT: AtomicPtr<()> = AtomicPtr::new(null::<()>() as *mut ());
    [INIT; 256]
};

pub(crate) fn set_irq_handler(irq: u8, handler: fn(u8)) {
    if (irq as usize) < 16 {
        IRQ_HANDLERS[irq as usize].store(handler as *mut (), Ordering::Release);
    }
}

pub(crate) fn get_irq_handler(irq: u8) -> Option<fn(u8)> {
    if (irq as usize) >= 16 {
        return None;
    }
    let ptr = IRQ_HANDLERS[irq as usize].load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { core::mem::transmute::<*mut (), fn(u8)>(ptr) })
    }
}

pub(crate) fn set_syscall_handler(handler: fn(&mut InterruptFrame)) {
    SYSCALL_HANDLER.store(handler as *mut (), Ordering::Release);
}

pub(crate) fn get_syscall_handler() -> Option<fn(&mut InterruptFrame)> {
    let ptr = SYSCALL_HANDLER.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { core::mem::transmute::<*mut (), fn(&mut InterruptFrame)>(ptr) })
    }
}

pub(crate) fn set_other_handler(vec: u8, handler: fn(&mut InterruptFrame)) {
    OTHER_HANDLERS[vec as usize].store(handler as *mut (), Ordering::Release);
}

pub(crate) fn get_other_handler(vec: u8) -> Option<fn(&mut InterruptFrame)> {
    let ptr = OTHER_HANDLERS[vec as usize].load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { core::mem::transmute::<*mut (), fn(&mut InterruptFrame)>(ptr) })
    }
}
