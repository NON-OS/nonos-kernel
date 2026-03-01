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

use x86_64::PhysAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciBar {
    Memory32 {
        address: PhysAddr,
        size: u64,
        prefetchable: bool,
    },
    Memory64 {
        address: PhysAddr,
        size: u64,
        prefetchable: bool,
    },
    Memory {
        address: PhysAddr,
        size: usize,
        is_prefetchable: bool,
        is_64bit: bool,
    },
    Io {
        port: u16,
        size: u32,
    },
    NotPresent,
}

impl PciBar {
    pub fn address(&self) -> Option<PhysAddr> {
        match self {
            PciBar::Memory32 { address, .. } => Some(*address),
            PciBar::Memory64 { address, .. } => Some(*address),
            PciBar::Memory { address, .. } => Some(*address),
            _ => None,
        }
    }

    pub fn port(&self) -> Option<u16> {
        match self {
            PciBar::Io { port, .. } => Some(*port),
            _ => None,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            PciBar::Memory32 { size, .. } => *size,
            PciBar::Memory64 { size, .. } => *size,
            PciBar::Memory { size, .. } => *size as u64,
            PciBar::Io { size, .. } => *size as u64,
            PciBar::NotPresent => 0,
        }
    }

    pub fn is_memory(&self) -> bool {
        matches!(self, PciBar::Memory32 { .. } | PciBar::Memory64 { .. } | PciBar::Memory { .. })
    }

    pub fn is_io(&self) -> bool {
        matches!(self, PciBar::Io { .. })
    }

    pub fn is_64bit(&self) -> bool {
        match self {
            PciBar::Memory64 { .. } => true,
            PciBar::Memory { is_64bit, .. } => *is_64bit,
            _ => false,
        }
    }

    pub fn is_prefetchable(&self) -> bool {
        match self {
            PciBar::Memory32 { prefetchable, .. } => *prefetchable,
            PciBar::Memory64 { prefetchable, .. } => *prefetchable,
            PciBar::Memory { is_prefetchable, .. } => *is_prefetchable,
            _ => false,
        }
    }

    pub fn is_present(&self) -> bool {
        !matches!(self, PciBar::NotPresent)
    }

    pub fn mmio_region(&self) -> Option<(PhysAddr, usize)> {
        match self {
            PciBar::Memory32 { address, size, .. } => Some((*address, *size as usize)),
            PciBar::Memory64 { address, size, .. } => Some((*address, *size as usize)),
            PciBar::Memory { address, size, .. } => Some((*address, *size)),
            _ => None,
        }
    }

    pub fn mmio_virt(&self) -> Option<(x86_64::VirtAddr, usize)> {
        self.mmio_region()
            .map(|(phys, size)| (x86_64::VirtAddr::new(phys.as_u64()), size))
    }
}

impl Default for PciBar {
    fn default() -> Self {
        PciBar::NotPresent
    }
}
