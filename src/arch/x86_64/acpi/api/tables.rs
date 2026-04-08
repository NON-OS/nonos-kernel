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

use alloc::vec::Vec;

use crate::arch::x86_64::acpi::data::{AcpiStats, NumaMemoryRegion, PcieSegment};
use crate::arch::x86_64::acpi::parser;
use crate::arch::x86_64::acpi::tables::PmProfile;

#[inline]
pub fn numa_regions() -> Vec<NumaMemoryRegion> {
    parser::numa_regions()
}

#[inline]
pub fn pcie_segments() -> Vec<PcieSegment> {
    parser::pcie_segments()
}

#[inline]
pub fn hpet_address() -> Option<u64> {
    parser::hpet_address()
}

#[inline]
pub fn pm_profile() -> Option<PmProfile> {
    parser::pm_profile()
}

#[inline]
pub fn sci_interrupt() -> Option<u16> {
    parser::sci_interrupt()
}

#[inline]
pub fn stats() -> AcpiStats {
    parser::stats()
}

#[inline]
pub fn has_table(signature: &[u8; 4]) -> bool {
    parser::has_table(signature)
}

#[inline]
pub fn table_address(signature: &[u8; 4]) -> Option<u64> {
    parser::table_address(signature)
}
