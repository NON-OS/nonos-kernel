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
use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;

use super::super::constants::IDT_ENTRIES;
use super::super::entry::IdtEntry;
use super::super::error::IdtError;
use super::super::state::{IDT, INITIALIZED};
use super::super::table::IdtPtr;
use super::init_exceptions::setup_exceptions;
use super::init_irqs::setup_irqs;
use super::pic::remap_pic;

pub fn init() -> Result<(), IdtError> {
    use super::super::state::INITIALIZING;
    if !INITIALIZING.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
        while !INITIALIZED.load(Ordering::Acquire) { core::hint::spin_loop(); }
        return Err(IdtError::AlreadyInitialized);
    }
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
        let idt = &mut *addr_of_mut!(IDT);
        setup_exceptions(idt);
        setup_irqs(idt);
        remap_pic();
        load_idt();
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

unsafe fn load_idt() {
    unsafe {
        let idt_ptr = addr_of_mut!(IDT);
        let ptr = IdtPtr {
            limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
            base: (*idt_ptr).entries.as_ptr() as u64,
        };
        asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack, preserves_flags));
    }
}

#[inline]
pub fn is_initialized() -> bool { INITIALIZED.load(Ordering::Acquire) }
