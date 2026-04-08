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

use crate::arch::x86_64::acpi::data::{InterruptOverride, IoApicInfo, NmiConfig};
use crate::arch::x86_64::acpi::parser;

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
