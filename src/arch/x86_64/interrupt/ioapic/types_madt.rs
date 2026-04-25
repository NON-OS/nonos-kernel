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
