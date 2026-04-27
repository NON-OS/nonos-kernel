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

use super::super::layout;
use x86_64::{PhysAddr, VirtAddr};

#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + layout::DIRECTMAP_BASE)
}

#[inline]
pub fn virt_to_phys(virt: VirtAddr) -> Option<PhysAddr> {
    if virt.as_u64() >= layout::DIRECTMAP_BASE
        && virt.as_u64() < layout::DIRECTMAP_BASE + layout::DIRECTMAP_SIZE
    {
        Some(PhysAddr::new(virt.as_u64() - layout::DIRECTMAP_BASE))
    } else {
        None
    }
}
