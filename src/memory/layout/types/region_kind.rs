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
pub enum RegionKind {
    Available,
    Usable,
    Reserved,
    Acpi,
    Mmio,
    Kernel,
    Boot,
    Unknown,
}

impl RegionKind {
    #[inline]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Usable | Self::Available)
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "Available",
            Self::Usable => "Usable",
            Self::Reserved => "Reserved",
            Self::Acpi => "ACPI",
            Self::Mmio => "MMIO",
            Self::Kernel => "Kernel",
            Self::Boot => "Boot",
            Self::Unknown => "Unknown",
        }
    }
}
