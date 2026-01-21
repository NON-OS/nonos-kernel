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

use super::sdt::{SdtHeader, GenericAddress};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageProtection {
    NoGuarantee,
    Protected4K,
    Protected64K,
    Unknown(u8),
}

impl PageProtection {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::NoGuarantee,
            1 => Self::Protected4K,
            2 => Self::Protected64K,
            v => Self::Unknown(v),
        }
    }
}

pub mod registers {
    pub const GCAP_ID: u64 = 0x000;
    pub const GCONF: u64 = 0x010;
    pub const GINTR_STS: u64 = 0x020;
    pub const MAIN_CNT: u64 = 0x0F0;

    pub const fn timer_config(n: u8) -> u64 {
        0x100 + (n as u64) * 0x20
    }

    pub const fn timer_comparator(n: u8) -> u64 {
        0x108 + (n as u64) * 0x20
    }

    pub const fn timer_fsb_route(n: u8) -> u64 {
        0x110 + (n as u64) * 0x20
    }
}

pub mod gcap_bits {
    pub const REV_ID_MASK: u64 = 0xFF;
    pub const NUM_TIM_CAP_SHIFT: u64 = 8;
    pub const NUM_TIM_CAP_MASK: u64 = 0x1F << NUM_TIM_CAP_SHIFT;
    pub const COUNT_SIZE_CAP: u64 = 1 << 13;
    pub const LEG_RT_CAP: u64 = 1 << 15;
    pub const VENDOR_ID_SHIFT: u64 = 16;
    pub const VENDOR_ID_MASK: u64 = 0xFFFF << VENDOR_ID_SHIFT;
    pub const COUNTER_CLK_PERIOD_SHIFT: u64 = 32;
}

pub mod gconf_bits {
    pub const ENABLE_CNF: u64 = 1 << 0;
    pub const LEG_RT_CNF: u64 = 1 << 1;
}

pub mod timer_bits {
    pub const RESERVED0: u64 = 1 << 0;
    pub const INT_TYPE_CNF: u64 = 1 << 1;
    pub const INT_ENB_CNF: u64 = 1 << 2;
    pub const TYPE_CNF: u64 = 1 << 3;
    pub const PER_INT_CAP: u64 = 1 << 4;
    pub const SIZE_CAP: u64 = 1 << 5;
    pub const VAL_SET_CNF: u64 = 1 << 6;
    pub const RESERVED1: u64 = 1 << 7;
    pub const MODE32_CNF: u64 = 1 << 8;
    pub const INT_ROUTE_SHIFT: u64 = 9;
    pub const INT_ROUTE_MASK: u64 = 0x1F << INT_ROUTE_SHIFT;
    pub const FSB_EN_CNF: u64 = 1 << 14;
    pub const FSB_INT_DEL_CAP: u64 = 1 << 15;
    pub const INT_ROUTE_CAP_SHIFT: u64 = 32;
}

pub mod int_type {
    pub const EDGE_TRIGGERED: u64 = 0;
    pub const LEVEL_TRIGGERED: u64 = 1;
}

pub const FEMTOSECONDS_PER_SECOND: u64 = 1_000_000_000_000_000;
pub const MIN_PERIOD_FS: u64 = 100_000;
pub const MAX_PERIOD_FS: u64 = 100_000_000_000_000;
