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

use core::sync::atomic::{AtomicBool, AtomicU64};

use crate::arch::x86_64::idt::constants::IDT_ENTRIES;
use crate::arch::x86_64::idt::entry::InterruptFrame;
use crate::arch::x86_64::idt::table::Idt;

pub(crate) static mut IDT: Idt = Idt::new();
pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static INTERRUPT_COUNTS: [AtomicU64; IDT_ENTRIES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; IDT_ENTRIES]
};

pub(crate) static TOTAL_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static EXCEPTION_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static mut IRQ_HANDLERS: [Option<fn(u8)>; 16] = [None; 16];
pub(crate) static mut SYSCALL_HANDLER: Option<fn(&mut InterruptFrame)> = None;
pub(crate) static mut OTHER_HANDLERS: [Option<fn(&mut InterruptFrame)>; 256] = [None; 256];
