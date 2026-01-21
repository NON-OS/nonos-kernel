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

//! ACPI API - Convenience functions for ACPI queries.

use alloc::vec::Vec;

use super::data::{
    AcpiStats, InterruptOverride, IoApicInfo, NmiConfig, NumaMemoryRegion, PcieSegment,
    ProcessorInfo,
};
use super::error::AcpiResult;
use super::parser;
use super::tables::PmProfile;

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

pub mod madt {
    use super::*;

    #[derive(Debug)]
    pub struct ParsedMadt {
        pub lapic_addr: u64,
        pub ioapics: Vec<IoApicInfo>,
        pub isos: Vec<InterruptOverride>,
        pub nmis: Vec<NmiConfig>,
    }

    pub fn parse_madt() -> Option<ParsedMadt> {
        Some(ParsedMadt {
            lapic_addr: parser::lapic_address()?,
            ioapics: parser::ioapics(),
            isos: parser::interrupt_overrides(),
            nmis: parser::nmi_configs(),
        })
    }
}
