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

use crate::arch::x86_64::acpi::data::{InterruptOverride, IoApicInfo, NmiConfig, ProcessorInfo};
use crate::arch::x86_64::acpi::error::AcpiResult;
use crate::arch::x86_64::acpi::parser;

#[inline]
pub fn init() -> AcpiResult<()> {
    parser::init()
}

#[inline]
pub fn is_initialized() -> bool {
    parser::is_initialized()
}

#[inline]
pub fn revision() -> Option<u8> {
    parser::revision()
}

#[inline]
pub fn oem_id() -> Option<[u8; 6]> {
    parser::oem_id()
}

#[inline]
pub fn lapic_address() -> Option<u64> {
    parser::lapic_address()
}

#[inline]
pub fn has_legacy_pics() -> Option<bool> {
    parser::has_legacy_pics()
}

#[inline]
pub fn processors() -> Vec<ProcessorInfo> {
    parser::processors()
}

#[inline]
pub fn ioapics() -> Vec<IoApicInfo> {
    parser::ioapics()
}

#[inline]
pub fn interrupt_overrides() -> Vec<InterruptOverride> {
    parser::interrupt_overrides()
}

#[inline]
pub fn nmi_configs() -> Vec<NmiConfig> {
    parser::nmi_configs()
}
