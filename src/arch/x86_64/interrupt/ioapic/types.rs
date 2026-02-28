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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rte {
    pub vector: u8,
    pub delivery: u8,
    pub logical: bool,
    pub active_low: bool,
    pub level_trigger: bool,
    pub masked: bool,
    pub dest_apic_id: u32,
}

impl Rte {
    pub const fn fixed(vector: u8, dest_apic_id: u32) -> Self {
        Self {
            vector,
            delivery: 0,
            logical: false,
            active_low: false,
            level_trigger: false,
            masked: true,
            dest_apic_id,
        }
    }

    pub const fn nmi(dest_apic_id: u32) -> Self {
        Self {
            vector: 0,
            delivery: 4,
            logical: false,
            active_low: false,
            level_trigger: false,
            masked: true,
            dest_apic_id,
        }
    }

    pub fn to_u32s(self) -> (u32, u32) {
        let mut low = self.vector as u32;
        low |= (self.delivery as u32) << 8;
        if self.logical { low |= 1 << 11; }
        if self.active_low { low |= 1 << 13; }
        if self.level_trigger { low |= 1 << 15; }
        if self.masked { low |= 1 << 16; }
        let high = (self.dest_apic_id & 0xFF) << 24;
        (low, high)
    }

    pub fn from_u32s(low: u32, high: u32) -> Self {
        Self {
            vector: (low & 0xFF) as u8,
            delivery: ((low >> 8) & 0x7) as u8,
            logical: (low & (1 << 11)) != 0,
            active_low: (low & (1 << 13)) != 0,
            level_trigger: (low & (1 << 15)) != 0,
            masked: (low & (1 << 16)) != 0,
            dest_apic_id: (high >> 24) & 0xFF,
        }
    }

    pub(crate) fn flags_bits(self) -> u32 {
        let mut f = 0u32;
        if self.logical { f |= 1 << 0; }
        if self.active_low { f |= 1 << 1; }
        if self.level_trigger { f |= 1 << 2; }
        if self.masked { f |= 1 << 3; }
        f | ((self.delivery as u32) << 8)
    }
}

impl Default for Rte {
    fn default() -> Self {
        Self::fixed(0, 0)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MadtIoApic {
    pub phys_base: u64,
    pub gsi_base: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct MadtIso {
    pub bus_irq: u8,
    pub gsi: u32,
    pub flags: IsoFlags,
}

#[derive(Clone, Copy, Debug)]
pub struct MadtNmi {
    pub cpu: u32,
    pub lint: u8,
    pub flags: IsoFlags,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct IsoFlags: u16 {
        const POLARITY_ACTIVE_HIGH = 0b00;
        const POLARITY_ACTIVE_LOW  = 0b10;
        const TRIGGER_EDGE         = 0b0000_0100;
        const TRIGGER_LEVEL        = 0b0000_1000;
    }
}

impl IsoFlags {
    pub fn from_polarity_trigger(polarity: u8, trigger: u8) -> Self {
        let mut flags = Self::empty();
        if polarity == 3 {
            flags |= Self::POLARITY_ACTIVE_LOW;
        }
        if trigger == 3 {
            flags |= Self::TRIGGER_LEVEL;
        } else if trigger == 1 {
            flags |= Self::TRIGGER_EDGE;
        }
        flags
    }
}
