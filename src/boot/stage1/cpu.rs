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
//
/// # Safety: CPUID instruction is always safe on x86_64 processors.
#[inline]
pub fn read_apic_id() -> u32 {
    let result = unsafe { core::arch::x86_64::__cpuid(1) };
    (result.ebx >> 24) & 0xFF
}
/// # Safety {
/// Must be called exactly once for the BSP during early boot.
/// Must be called before any interrupt handling or task switching.
/// }
pub unsafe fn init_cpu_structures() -> Result<(), &'static str> {
    crate::arch::x86_64::gdt::init().map_err(|_| "Failed to initialize GDT")?;
    crate::arch::x86_64::idt::init();
    Ok(())
}
