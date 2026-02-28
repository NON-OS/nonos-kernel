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

pub fn cpu_yield() {
    // SAFETY: hlt is always safe to execute
    unsafe { core::arch::asm!("hlt"); }
}

pub fn idle_cpu() {
    // SAFETY: sti and hlt are safe, atomic to prevent race condition
    unsafe {
        core::arch::asm!("sti; hlt", options(nomem, nostack));
    }
}

pub fn disable_interrupts() {
    // SAFETY: cli is always safe
    unsafe { core::arch::asm!("cli"); }
}

pub fn enable_interrupts() {
    // SAFETY: sti is always safe
    unsafe { core::arch::asm!("sti"); }
}

pub fn get_cpu_id() -> u32 {
    0
}

pub fn init_cpu_features() {
}
