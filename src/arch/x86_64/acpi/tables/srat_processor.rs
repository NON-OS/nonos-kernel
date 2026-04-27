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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratProcessorAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain_low: u8,
    pub apic_id: u8,
    pub flags: u32,
    pub sapic_eid: u8,
    pub proximity_domain_high: [u8; 3],
    pub clock_domain: u32,
}

impl SratProcessorAffinity {
    pub const ENABLED: u32 = 1 << 0;
    pub fn proximity_domain(&self) -> u32 {
        self.proximity_domain_low as u32
            | ((self.proximity_domain_high[0] as u32) << 8)
            | ((self.proximity_domain_high[1] as u32) << 16)
            | ((self.proximity_domain_high[2] as u32) << 24)
    }
    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratX2ApicAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub reserved1: u16,
    pub proximity_domain: u32,
    pub x2apic_id: u32,
    pub flags: u32,
    pub clock_domain: u32,
    pub reserved2: u32,
}

impl SratX2ApicAffinity {
    pub const ENABLED: u32 = 1 << 0;
    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }
}
