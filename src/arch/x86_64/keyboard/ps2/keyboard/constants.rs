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

pub const CMD_SET_LEDS: u8 = 0xED;
pub const CMD_GET_SET_SCANCODE: u8 = 0xF0;
pub const CMD_SET_TYPEMATIC: u8 = 0xF3;
pub const CMD_ENABLE_SCANNING: u8 = 0xF4;
pub const CMD_DISABLE_SCANNING: u8 = 0xF5;
pub const CMD_RESET: u8 = 0xFF;

pub const RESP_ACK: u8 = 0xFA;
pub const RESP_SELF_TEST_PASS: u8 = 0xAA;
