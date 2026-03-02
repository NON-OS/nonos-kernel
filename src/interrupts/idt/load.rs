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

use core::sync::atomic::{AtomicBool, Ordering};

use super::table::IDT;

static IDT_LOADED: AtomicBool = AtomicBool::new(false);

pub fn load() {
    IDT.load();
    IDT_LOADED.store(true, Ordering::Release);
}

pub fn is_loaded() -> bool {
    IDT_LOADED.load(Ordering::Acquire)
}

pub fn enable_interrupts() {
    x86_64::instructions::interrupts::enable();
}

pub fn disable_interrupts() {
    x86_64::instructions::interrupts::disable();
}

pub fn are_interrupts_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}

pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    x86_64::instructions::interrupts::without_interrupts(f)
}

pub fn halt() {
    x86_64::instructions::hlt();
}

pub fn halt_loop() -> ! {
    loop {
        disable_interrupts();
        halt();
    }
}
