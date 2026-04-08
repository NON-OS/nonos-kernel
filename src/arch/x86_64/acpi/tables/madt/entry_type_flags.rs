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

pub mod polarity {
    pub const CONFORMS: u8 = 0;
    pub const ACTIVE_HIGH: u8 = 1;
    pub const RESERVED: u8 = 2;
    pub const ACTIVE_LOW: u8 = 3;
}

pub mod trigger {
    pub const CONFORMS: u8 = 0;
    pub const EDGE: u8 = 1;
    pub const RESERVED: u8 = 2;
    pub const LEVEL: u8 = 3;
}
