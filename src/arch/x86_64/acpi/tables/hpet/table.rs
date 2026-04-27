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

use super::protection::PageProtection;
use crate::arch::x86_64::acpi::tables::sdt::{GenericAddress, SdtHeader};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Hpet {
    pub header: SdtHeader,
    pub event_timer_block_id: u32,
    pub base_address: GenericAddress,
    pub hpet_number: u8,
    pub minimum_tick: u16,
    pub page_protection: u8,
}

impl Hpet {
    pub fn comparator_count(&self) -> u8 {
        ((self.event_timer_block_id >> 8) & 0x1F) as u8 + 1
    }

    pub fn vendor_id(&self) -> u16 {
        (self.event_timer_block_id >> 16) as u16
    }

    pub fn hardware_revision(&self) -> u8 {
        self.event_timer_block_id as u8
    }

    pub fn is_64bit(&self) -> bool {
        self.event_timer_block_id & (1 << 13) != 0
    }

    pub fn supports_legacy_replacement(&self) -> bool {
        self.event_timer_block_id & (1 << 15) != 0
    }

    pub fn address(&self) -> u64 {
        self.base_address.address
    }

    pub fn is_valid(&self) -> bool {
        self.base_address.is_valid()
    }

    pub fn page_protection_attr(&self) -> PageProtection {
        PageProtection::from_u8(self.page_protection & 0x0F)
    }

    pub fn oem_attr(&self) -> u8 {
        (self.page_protection >> 4) & 0x0F
    }
}
