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

pub const DATA_PORT: u16 = 0x60;
pub const STATUS_PORT: u16 = 0x64;
pub const COMMAND_PORT: u16 = 0x64;
pub const STATUS_OUTPUT_FULL: u8 = 1 << 0;
pub const STATUS_INPUT_FULL: u8 = 1 << 1;
pub const CMD_READ_CONFIG: u8 = 0x20;
pub const CMD_WRITE_CONFIG: u8 = 0x60;
pub const CMD_DISABLE_PORT2: u8 = 0xA7;
pub const CMD_ENABLE_PORT2: u8 = 0xA8;
pub const CMD_TEST_PORT2: u8 = 0xA9;
pub const CMD_SELF_TEST: u8 = 0xAA;
pub const CMD_TEST_PORT1: u8 = 0xAB;
pub const CMD_DISABLE_PORT1: u8 = 0xAD;
pub const CMD_ENABLE_PORT1: u8 = 0xAE;
pub const CMD_WRITE_PORT2: u8 = 0xD4;
pub const CONFIG_PORT1_IRQ: u8 = 1 << 0;
pub const CONFIG_PORT2_IRQ: u8 = 1 << 1;
pub const CONFIG_PORT2_CLOCK: u8 = 1 << 5;
pub const CONFIG_PORT1_TRANSLATE: u8 = 1 << 6;
pub const SELF_TEST_PASS: u8 = 0x55;
pub const PORT_TEST_PASS: u8 = 0x00;
pub const TIMEOUT_CYCLES: u32 = 100_000;
