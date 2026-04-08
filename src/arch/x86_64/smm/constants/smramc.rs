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

pub const SMRAMC_REGISTER: u16 = 0x88;

pub mod bits {
    pub const G_SMRAME: u8 = 0x08;
    pub const D_LCK: u8 = 0x10;
    pub const D_CLS: u8 = 0x20;
    pub const D_OPEN: u8 = 0x40;
}
