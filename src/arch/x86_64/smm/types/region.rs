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
pub enum SmmRegionType {
    Aseg,
    Hseg,
    Tseg,
    Unknown,
}

impl SmmRegionType {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Aseg => "ASEG",
            Self::Hseg => "HSEG",
            Self::Tseg => "TSEG",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SmmRegion {
    pub base: u64,
    pub size: u64,
    pub region_type: SmmRegionType,
    pub protected: bool,
    pub open: bool,
}

impl SmmRegion {
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size)
    }

    pub const fn contains_range(&self, start: u64, size: u64) -> bool {
        start >= self.base && start.saturating_add(size) <= self.base.saturating_add(self.size)
    }
}
