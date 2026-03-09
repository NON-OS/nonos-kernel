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

use super::core::Rtl8139Device;
use crate::drivers::rtl8139::constants::reg;
use crate::drivers::rtl8139::io::{inl, inw};

impl Rtl8139Device {
    pub(crate) fn read_mac_address(&mut self) {
        let mac0 = inl(self.io_base + reg::IDR0);
        let mac4 = inw(self.io_base + reg::IDR4);

        self.mac_address[0] = (mac0 & 0xFF) as u8;
        self.mac_address[1] = ((mac0 >> 8) & 0xFF) as u8;
        self.mac_address[2] = ((mac0 >> 16) & 0xFF) as u8;
        self.mac_address[3] = ((mac0 >> 24) & 0xFF) as u8;
        self.mac_address[4] = (mac4 & 0xFF) as u8;
        self.mac_address[5] = ((mac4 >> 8) & 0xFF) as u8;
    }
}
