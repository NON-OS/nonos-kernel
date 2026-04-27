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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegionType {
    Available,
    Reserved,
    Kernel,
    User,
    Stack,
    Heap,
    Mmio,
    Firmware,
    Bootloader,
    Dma,
    Guard,
    Shared,
}

impl RegionType {
    pub const fn is_allocatable(&self) -> bool {
        matches!(self, Self::Available)
    }
    pub const fn is_kernel(&self) -> bool {
        matches!(self, Self::Kernel | Self::Stack | Self::Heap)
    }
    pub const fn is_reserved(&self) -> bool {
        matches!(self, Self::Reserved | Self::Firmware | Self::Bootloader | Self::Guard)
    }
}

impl Default for RegionType {
    fn default() -> Self {
        Self::Available
    }
}
