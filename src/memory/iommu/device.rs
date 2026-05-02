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

// LIMIT: this newtype encodes a PCI bus/device/function only. SMMU
// stream IDs and other non-PCI bus identifiers will need either an
// enum or sibling newtypes when those backends arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceAddress(u32);

impl DeviceAddress {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn pci(bus: u8, device: u8, function: u8) -> Self {
        Self(((bus as u32) << 8) | ((device as u32) << 3) | (function as u32 & 0x7))
    }

    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    pub const fn pci_bus(&self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }

    pub const fn pci_device(&self) -> u8 {
        ((self.0 >> 3) & 0x1F) as u8
    }

    pub const fn pci_function(&self) -> u8 {
        (self.0 & 0x7) as u8
    }
}
