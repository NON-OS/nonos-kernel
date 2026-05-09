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

use super::shootdown::ASID_KERNEL;
use crate::memory::addr::VirtAddr;
use crate::memory::paging::constants::{pml4_index, KERNEL_PML4_START};

pub(super) fn is_kernel_half(va: VirtAddr) -> bool {
    pml4_index(va.as_u64()) >= KERNEL_PML4_START
}

pub(super) fn mutation_asid(va: VirtAddr, active_asid: Option<u32>) -> u32 {
    if is_kernel_half(va) {
        ASID_KERNEL
    } else {
        active_asid.unwrap_or(ASID_KERNEL)
    }
}
