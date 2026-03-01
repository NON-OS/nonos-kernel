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

use core::fmt;
use crate::drivers::pci::constants::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassCode {
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

impl ClassCode {
    pub const fn new(class: u8, subclass: u8, prog_if: u8) -> Self {
        Self { class, subclass, prog_if }
    }

    pub fn name(&self) -> &'static str {
        class_name(self.class)
    }

    pub fn is_bridge(&self) -> bool {
        self.class == CLASS_BRIDGE
    }

    pub fn is_storage(&self) -> bool {
        self.class == CLASS_MASS_STORAGE
    }

    pub fn is_network(&self) -> bool {
        self.class == CLASS_NETWORK
    }

    pub fn is_display(&self) -> bool {
        self.class == CLASS_DISPLAY
    }

    pub fn is_usb(&self) -> bool {
        self.class == CLASS_SERIAL_BUS && self.subclass == SUBCLASS_SERIAL_USB
    }

    pub fn is_nvme(&self) -> bool {
        self.class == CLASS_MASS_STORAGE && self.subclass == SUBCLASS_STORAGE_NVM
    }

    pub fn is_ahci(&self) -> bool {
        self.class == CLASS_MASS_STORAGE && self.subclass == SUBCLASS_STORAGE_SATA
    }
}

impl fmt::Display for ClassCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}.{:02x}.{:02x}", self.class, self.subclass, self.prog_if)
    }
}
