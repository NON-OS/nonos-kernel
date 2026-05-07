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

// Counts non-zero entries in a PML4-shaped 512-u64 page,
// addressed by physical address through the directmap. Caller is
// responsible for ensuring `phys_to_virt` resolves to a valid
// kernel-half VA before calling this.

pub(super) unsafe fn count_pml4_entries(
    pml4_phys: u64,
    range: core::ops::Range<usize>,
) -> usize {
    let virt = crate::memory::unified::phys_to_virt(crate::memory::addr::PhysAddr::new(pml4_phys));
    let table = unsafe { &*(virt.as_u64() as *const [u64; 512]) };
    table[range].iter().filter(|&&entry| entry != 0).count()
}
