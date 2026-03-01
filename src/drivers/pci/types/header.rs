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

use crate::drivers::pci::constants::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderType {
    Standard,
    PciToPciBridge,
    CardBusBridge,
    Unknown(u8),
}

impl From<u8> for HeaderType {
    fn from(value: u8) -> Self {
        match value & 0x7F {
            HDR_TYPE_STANDARD => HeaderType::Standard,
            HDR_TYPE_BRIDGE => HeaderType::PciToPciBridge,
            HDR_TYPE_CARDBUS => HeaderType::CardBusBridge,
            other => HeaderType::Unknown(other),
        }
    }
}

impl HeaderType {
    pub fn is_multifunction(raw: u8) -> bool {
        (raw & HDR_TYPE_MULTIFUNCTION) != 0
    }
}
