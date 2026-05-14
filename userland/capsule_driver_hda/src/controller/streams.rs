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

pub fn input_streams(gcap: u16) -> u8 {
    ((gcap >> 8) & 0x0f) as u8
}

pub fn output_streams(gcap: u16) -> u8 {
    ((gcap >> 12) & 0x0f) as u8
}

pub fn bidi_streams(gcap: u16) -> u8 {
    ((gcap >> 3) & 0x1f) as u8
}

pub fn addr64(gcap: u16) -> u8 {
    (gcap & 1) as u8
}
