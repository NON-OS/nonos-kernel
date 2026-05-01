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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granule {
    G4K,
    G16K,
    G64K,
}

pub const GRANULE_4K: Granule = Granule::G4K;
pub const GRANULE_16K: Granule = Granule::G16K;
pub const GRANULE_64K: Granule = Granule::G64K;

impl Granule {
    pub const fn page_size(&self) -> usize {
        match self {
            Granule::G4K => 4096,
            Granule::G16K => 16384,
            Granule::G64K => 65536,
        }
    }

    pub const fn page_shift(&self) -> usize {
        match self {
            Granule::G4K => 12,
            Granule::G16K => 14,
            Granule::G64K => 16,
        }
    }

    pub const fn entries_per_table(&self) -> usize {
        match self {
            Granule::G4K => 512,
            Granule::G16K => 2048,
            Granule::G64K => 8192,
        }
    }

    pub const fn table_shift(&self) -> usize {
        match self {
            Granule::G4K => 9,
            Granule::G16K => 11,
            Granule::G64K => 13,
        }
    }

    pub const fn levels(&self) -> usize {
        match self {
            Granule::G4K => 4,
            Granule::G16K => 4,
            Granule::G64K => 3,
        }
    }

    pub const fn block_size(&self, level: usize) -> Option<usize> {
        match (self, level) {
            (Granule::G4K, 1) => Some(1 << 30),
            (Granule::G4K, 2) => Some(1 << 21),
            (Granule::G16K, 2) => Some(1 << 25),
            (Granule::G64K, 2) => Some(1 << 29),
            _ => None,
        }
    }

    pub fn tcr_granule_bits(&self) -> u64 {
        match self {
            Granule::G4K => 0b00,
            Granule::G16K => 0b10,
            Granule::G64K => 0b01,
        }
    }

    pub fn index_at_level(&self, addr: u64, level: usize) -> usize {
        let shift = self.page_shift() + self.table_shift() * (self.levels() - 1 - level);
        let mask = self.entries_per_table() - 1;
        ((addr >> shift) as usize) & mask
    }
}

pub const fn page_offset(addr: u64, granule: Granule) -> usize {
    (addr & ((granule.page_size() - 1) as u64)) as usize
}

pub const fn page_align_down(addr: u64, granule: Granule) -> u64 {
    addr & !((granule.page_size() - 1) as u64)
}

pub const fn page_align_up(addr: u64, granule: Granule) -> u64 {
    let mask = (granule.page_size() - 1) as u64;
    (addr + mask) & !mask
}

pub const fn pages_needed(size: u64, granule: Granule) -> u64 {
    (size + (granule.page_size() - 1) as u64) / granule.page_size() as u64
}
