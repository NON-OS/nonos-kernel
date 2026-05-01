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

use super::phys::PhysAddr;
use super::virt::VirtAddr;

impl From<x86_64::PhysAddr> for PhysAddr {
    fn from(a: x86_64::PhysAddr) -> Self {
        Self::new(a.as_u64())
    }
}

impl From<PhysAddr> for x86_64::PhysAddr {
    fn from(a: PhysAddr) -> Self {
        x86_64::PhysAddr::new(a.as_u64())
    }
}

impl From<x86_64::VirtAddr> for VirtAddr {
    fn from(a: x86_64::VirtAddr) -> Self {
        Self::new(a.as_u64())
    }
}

impl From<VirtAddr> for x86_64::VirtAddr {
    fn from(a: VirtAddr) -> Self {
        x86_64::VirtAddr::new(a.as_u64())
    }
}
