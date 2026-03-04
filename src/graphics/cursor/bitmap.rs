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

pub(super) const CURSOR_WIDTH: u32 = 12;
pub(super) const CURSOR_HEIGHT: u32 = 16;

pub(super) const CURSOR_BITMAP: [u16; 16] = [
    0b1000000000000000,
    0b1100000000000000,
    0b1110000000000000,
    0b1111000000000000,
    0b1111100000000000,
    0b1111110000000000,
    0b1111111000000000,
    0b1111111100000000,
    0b1111111110000000,
    0b1111110000000000,
    0b1101110000000000,
    0b1000111000000000,
    0b0000111000000000,
    0b0000011100000000,
    0b0000011100000000,
    0b0000001100000000,
];

pub(super) const CURSOR_MASK: [u16; 16] = [
    0b1100000000000000,
    0b1110000000000000,
    0b1111000000000000,
    0b1111100000000000,
    0b1111110000000000,
    0b1111111000000000,
    0b1111111100000000,
    0b1111111110000000,
    0b1111111111000000,
    0b1111111111000000,
    0b1111111000000000,
    0b1101111100000000,
    0b1000111100000000,
    0b0000111110000000,
    0b0000111110000000,
    0b0000011110000000,
];
