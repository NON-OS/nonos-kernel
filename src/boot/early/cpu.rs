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

pub fn read_apic_id() -> u32 {
    let result = core::arch::x86_64::__cpuid(1);
    (result.ebx >> 24) & 0xFF
}

pub unsafe fn init_cpu_structures() -> Result<(), &'static str> {
    // SAFETY: Must be called once for BSP during boot
    crate::arch::x86_64::gdt::init().map_err(|_| "Failed to initialize GDT")?;
    crate::arch::x86_64::idt::init();
    Ok(())
}
